package web

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/prefixdb"
)

type lookupHit struct {
	Kind        string
	ID          uint
	Target      string
	State       string
	Reason      string
	RequestedBy string
	ApprovedBy  string
	CreatedAt   string
	ExpiresAt   string
	Enforced    bool
	CanRollback bool
}

func (h *Handler) lookupPage(c *gin.Context) {
	u := h.currentUser(c)
	c.HTML(http.StatusOK, "lookup.html", gin.H{
		"u": u, "nav": navSections,
		"csrf": h.csrfTokenFor(c),
	})
}

func (h *Handler) lookupSearch(c *gin.Context) {
	u := h.currentUser(c)
	nav := navSections
	raw := strings.TrimSpace(c.PostForm("ip"))

	ip := net.ParseIP(raw)
	if ip == nil || ip.To4() == nil {
		c.HTML(http.StatusBadRequest, "lookup.html", gin.H{
			"u": u, "nav": nav, "query": raw,
			"err":  fmt.Sprintf("非法 IPv4 地址:%q", raw),
			"csrf": h.csrfTokenFor(c),
		})
		return
	}
	queryIP := ip.To4().String()
	queryAddr, err := netip.ParseAddr(queryIP)
	if err != nil {
		c.HTML(http.StatusBadRequest, "lookup.html", gin.H{
			"u": u, "nav": nav, "query": raw,
			"err":  fmt.Sprintf("非法 IPv4 地址:%q", raw),
			"csrf": h.csrfTokenFor(c),
		})
		return
	}

	var hits []lookupHit

	var reqs []model.BanRequest
	h.db.Where("target IN ? AND state IN ?", []string{queryIP, queryIP + "/32"}, []string{"active", "pending"}).
		Order("created_at desc").Find(&reqs)
	for _, r := range reqs {
		hit := lookupHit{
			Kind: "ban", ID: r.ID, Target: r.Target, State: r.State, Reason: r.Reason,
			CreatedAt: r.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if r.RequestedByID != nil {
			hit.RequestedBy = h.userLabel(*r.RequestedByID)
		}
		if r.ApprovedByID != nil {
			hit.ApprovedBy = h.userLabel(*r.ApprovedByID)
		}
		if r.ExpiresAt != nil {
			hit.ExpiresAt = r.ExpiresAt.Format("2006-01-02 15:04:05")
		}
		hit.Enforced = h.dispatchAcked(fmt.Sprintf("ban-%d-%s", r.ID, r.Target))
		hit.CanRollback = r.State == "active" || r.State == "pending"
		hits = append(hits, hit)
	}

	var scoped []model.ScopedBan
	h.db.Where("state IN ?", []string{"active", "pending"}).Order("created_at desc").Limit(200).Find(&scoped)
	pdb := prefixdb.Global()
	for _, sb := range scoped {
		if pdb == nil {
			continue
		}
		cidrs, err := pdb.Resolve(prefixdb.Selector{Country: sb.Country, ASN: sb.ASN})
		if err != nil {
			continue
		}
		matched := false
		for _, p := range cidrs {
			if p.Contains(queryAddr) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		hit := lookupHit{
			Kind: "scoped", ID: sb.ID, Target: sb.Label(), State: sb.State, Reason: sb.Reason,
			CreatedAt: sb.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if sb.RequestedByID != nil {
			hit.RequestedBy = h.userLabel(*sb.RequestedByID)
		}
		if sb.ApprovedByID != nil {
			hit.ApprovedBy = h.userLabel(*sb.ApprovedByID)
		}
		if sb.ExpiresAt != nil {
			hit.ExpiresAt = sb.ExpiresAt.Format("2006-01-02 15:04:05")
		}
		hit.Enforced = h.dispatchAcked(fmt.Sprintf("scoped-%d-%s", sb.ID, sb.TargetIP))
		hit.CanRollback = sb.State == "active" || sb.State == "pending"
		hits = append(hits, hit)
	}

	c.HTML(http.StatusOK, "lookup.html", gin.H{
		"u": u, "nav": nav, "query": raw, "hits": hits, "searched": true,
		"csrf": h.csrfTokenFor(c),
	})
}

func (h *Handler) lookupRollback(c *gin.Context) {
	u := h.currentUser(c)
	kind := c.Param("kind")

	switch kind {
	case "ban":
		var req model.BanRequest
		if h.db.First(&req, c.Param("id")).Error != nil {
			c.Redirect(http.StatusFound, "/lookup")
			return
		}
		if req.State != "active" && req.State != "pending" {
			c.Redirect(http.StatusFound, "/lookup")
			return
		}
		if req.State == "pending" {
			h.db.Model(&req).Update("state", "rejected")
			_ = model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "rolled_back", req.Target)
			c.Redirect(http.StatusFound, "/lookup")
			return
		}
		if err := h.revoker.RevokeGlobal(req.Target); err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
			return
		}
		now := time.Now()
		h.db.Model(&req).Updates(map[string]any{"state": "revoked", "cleared_at": now})
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "rolled_back", req.Target)
		c.Redirect(http.StatusFound, "/lookup")

	case "scoped":
		var sb model.ScopedBan
		if h.db.First(&sb, c.Param("id")).Error != nil {
			c.Redirect(http.StatusFound, "/lookup")
			return
		}
		if sb.State != "active" && sb.State != "pending" {
			c.Redirect(http.StatusFound, "/lookup")
			return
		}
		if sb.State == "pending" {
			h.db.Model(&sb).Update("state", "rejected")
			if sb.Global {
				h.quota.ReleaseGlobal(sb.PrefixCount)
			} else {
				h.quota.Release(sb.PrefixCount)
			}
			_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID), "rolled_back", sb.Label())
			c.Redirect(http.StatusFound, "/lookup")
			return
		}
		if sb.Global {
			prefixes, err := h.scopedGlobalDispatchPrefixes(&sb)
			if err != nil {
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
				return
			}
			for _, p := range prefixes {
				if err := h.revoker.RevokeGlobal(p); err != nil {
					c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
					return
				}
			}
		} else {
			prefixes, err := h.scopedDispatchPrefixes(&sb)
			if err != nil {
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
				return
			}
			if err := h.revoker.RevokeScoped(sb.TargetIP, prefixes); err != nil {
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
				return
			}
		}
		now := time.Now()
		h.db.Model(&sb).Updates(map[string]any{"state": "revoked", "revoked_at": now})
		if sb.Global {
			h.quota.ReleaseGlobal(sb.PrefixCount)
		} else {
			h.quota.Release(sb.PrefixCount)
		}
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID), "rolled_back", sb.Label())
		c.Redirect(http.StatusFound, "/lookup")

	default:
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "非法回滚类型"})
	}
}

func (h *Handler) userLabel(id uint) string {
	var u model.User
	if h.db.First(&u, id).Error != nil {
		return ""
	}
	return u.Label()
}

func (h *Handler) dispatchAcked(banID string) bool {
	var d model.Dispatch
	if h.db.Where("ban_id = ?", banID).First(&d).Error != nil {
		return false
	}
	return d.State == "acked"
}
