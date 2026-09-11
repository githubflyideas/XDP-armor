package web

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/approval"
	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/quota"
)

type Revoker interface {
	RevokeGlobal(target string) error
	RevokeScoped(targetIP string, prefixes []string) error
}

type Handler struct {
	db        *gorm.DB
	approvals *approval.Service
	sessions  *sessionStore
	quota     *quota.Tracker
	revoker   Revoker

	// decideMu 串行化所有"审批/驳回"的读-检查-写。
	//
	// 光靠 DB 层的 WHERE state='pending' 条件更新不够:SQLite 的
	// deferred 事务里先读后写,若期间别的事务提交了,升级写锁会直接返回
	// SQLITE_BUSY_SNAPSHOT——请求收到的是 500,而不是我们想给的 409。
	// 单进程单库的部署形态下,进程内互斥是最省事也最确定的答案;
	// 条件更新保留作纵深防御(执行器等其他进程仍可能并发改状态)。
	decideMu sync.Mutex
}

const sessionTTL = 8 * time.Hour

// Register 挂载全部路由,并返回构造出的 Handler。
// 返回值给测试用(需要读会话里的 CSRF token),生产调用方直接忽略即可。
func Register(r *gin.Engine, db *gorm.DB, revoker Revoker) *Handler {
	baseURL := envOr("XDPBAN_BASE_URL", "http://localhost:8080")
	h := &Handler{
		db:        db,
		approvals: approval.NewService(db, baseURL),
		sessions:  newSessionStore(sessionTTL),
		quota:     quota.NewTracker(),
		revoker:   revoker,
	}
	h.restoreQuota()
	r.SetHTMLTemplate(templates())

	r.GET("/login", h.loginPage)
	r.POST("/login", h.doLogin)
	r.GET("/logout", h.logout)

	r.GET("/approve/:token", h.approveShow)
	r.POST("/approve/:token", h.approveDo)

	r.GET("/favicon.ico", serveFavicon)

	auth := r.Group("/", h.requireLogin, h.requireCSRF)
	{
		auth.GET("/", h.dashboard)
		auth.GET("/dashboard", h.dashboard)
		auth.GET("/bans", h.bansList)
		auth.GET("/bans/new", h.banNew)
		auth.POST("/bans", h.banCreate)
		auth.POST("/bans/:id/approve", h.banApprove)
		auth.POST("/bans/:id/reject", h.banReject)
		auth.GET("/bans/:id", h.banDetail)

		auth.GET("/lookup", h.lookupPage)
		auth.POST("/lookup", h.lookupSearch)
		auth.POST("/lookup/:kind/:id/rollback", h.lookupRollback)

		auth.GET("/scoped", h.scopedBanList)
		auth.GET("/scoped/new", h.scopedBanNew)
		auth.POST("/scoped", h.scopedBanCreate)
		auth.GET("/scoped/asn-search", h.scopedASNSearch)
		auth.POST("/scoped/preview", h.scopedPreview)
		auth.POST("/scoped/:id/approve", h.scopedBanApprove)
		auth.POST("/scoped/:id/reject", h.scopedBanReject)
		auth.POST("/scoped/:id/revoke", h.scopedBanRevoke)

		auth.GET("/account", h.accountPage)
		auth.POST("/account/password", h.accountChangePassword)

		auth.GET("/prefixdb", h.prefixDBPage)
		auth.POST("/prefixdb/sync", h.prefixDBSync)
		auth.GET("/prefixdb/status", h.prefixDBStatus)
		auth.POST("/prefixdb/upload", h.prefixDBUpload)
		auth.POST("/prefixdb/overrides", h.prefixDBSaveOverride)

		auth.GET("/audit", h.auditLog)

		auth.GET("/report", h.reportPage)
		auth.GET("/report/export", h.reportExport)
	}

	return h
}

func (h *Handler) csrfTokenFor(c *gin.Context) string {
	tok, err := c.Cookie("sid")
	if err != nil {
		return ""
	}
	t, _ := h.sessions.CSRFToken(tok)
	return t
}

func (h *Handler) currentUser(c *gin.Context) *model.User {
	tok, err := c.Cookie("sid")
	if err != nil {
		return nil
	}
	uid, ok := h.sessions.Get(tok)
	if !ok {
		return nil
	}
	var u model.User
	if h.db.First(&u, uid).Error != nil || !u.Active {
		return nil
	}
	return &u
}

func (h *Handler) requireLogin(c *gin.Context) {
	if h.currentUser(c) == nil {
		c.Redirect(http.StatusFound, "/login")
		c.Abort()
	}
}

func (h *Handler) loginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func (h *Handler) doLogin(c *gin.Context) {
	var u model.User
	err := h.db.Where("username = ? AND active = ?", c.PostForm("username"), true).First(&u).Error
	if err != nil || !u.CheckPassword(c.PostForm("password")) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"err": "用户名或密码错误,或账号已停用"})
		return
	}
	tok := randToken()
	h.sessions.Put(tok, u.ID)

	secure := envOr("XDPBAN_COOKIE_SECURE", "") != ""
	c.SetCookie("sid", tok, int(sessionTTL.Seconds()), "/", "", secure, true)
	now := time.Now()
	h.db.Model(&u).Update("last_login_at", now)
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "User", itoa(u.ID), "login", "")
	c.Redirect(http.StatusFound, "/dashboard")
}

func (h *Handler) logout(c *gin.Context) {
	if tok, err := c.Cookie("sid"); err == nil {
		h.sessions.Delete(tok)
	}
	c.SetCookie("sid", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login")
}

func (h *Handler) dashboard(c *gin.Context) {
	u := h.currentUser(c)
	var pending, active, failed, driftCount int64
	h.db.Model(&model.BanRequest{}).Where("state = ?", "pending").Count(&pending)
	h.db.Model(&model.BanRequest{}).Where("state = ?", "active").Count(&active)
	h.db.Model(&model.Dispatch{}).Where("state = ?", "failed").Count(&failed)
	h.db.Model(&model.AuditLog{}).
		Where("event = ? AND occurred_at >= ?", "drift_detected", time.Now().Add(-24*time.Hour)).
		Count(&driftCount)
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"u": u, "nav": navSections,
		"pending": pending, "active": active, "failed": failed, "driftCount": driftCount,
	})
}

func (h *Handler) bansList(c *gin.Context) {
	u := h.currentUser(c)
	var reqs []model.BanRequest
	h.db.Order("created_at desc").Limit(200).Find(&reqs)
	c.HTML(http.StatusOK, "bans.html", gin.H{
		"u": u, "nav": navSections, "reqs": reqs,
		"csrf": h.csrfTokenFor(c),
	})
}

func (h *Handler) banNew(c *gin.Context) {
	u := h.currentUser(c)

	c.HTML(http.StatusOK, "ban_new.html", gin.H{
		"u": u, "nav": navSections,
		"target": strings.TrimSpace(c.Query("target")),
		"reason": strings.TrimSpace(c.Query("reason")),
		"csrf":   h.csrfTokenFor(c),
	})
}

func (h *Handler) banCreate(c *gin.Context) {
	u := h.currentUser(c)
	target := strings.TrimSpace(c.PostForm("target"))
	reason := strings.TrimSpace(c.PostForm("reason"))

	// fail 必须把 csrf / target / reason 一起回填。之前这三个错误分支只传了
	// err,重渲染出来的表单里 csrf_token 是空的 —— 用户改完再提交直接吃 403,
	// 看起来像"改对了反而更坏了"。自封确认要走的正是"勾上复选框再提交"这条路,
	// 没有回填就根本走不通。
	//
	// selfWarn 一旦置起就一直带着:后面还可能有别的失败(比如建记录失败),
	// 那时若把复选框收回去,已经勾过的确认就丢了,下次提交又会被拦。
	selfWarn := false
	selfAck := selfAcked(c)
	fail := func(code int, msg string) {
		c.HTML(code, "ban_new.html", gin.H{
			"u": u, "nav": navSections, "err": msg,
			"target": target, "reason": reason,
			"csrf":     h.csrfTokenFor(c),
			"selfWarn": selfWarn,
			"selfAck":  selfAck,
		})
	}

	if target == "" {
		fail(http.StatusBadRequest, "目标不能为空")
		return
	}

	if reason := h.guard().VetoReason(target); reason != "" {
		fail(http.StatusBadRequest, reason)
		return
	}

	// 保护集放行之后,再问一句"这条规则会不会切掉提交者此刻正用着的连接"。
	// 顺序有意如此:硬保护集的否决是终局的,自封只是要一次确认,不该抢在前面。
	if hit, locked := selfLockoutTarget(c, target); locked {
		selfWarn = true
		if !selfAck {
			fail(http.StatusBadRequest, selfLockoutMsgGlobal(hit))
			return
		}
	}

	ttl := h.nextTTL(target)

	req := model.BanRequest{
		ActionType: "ban", Target: target, Source: "manual",
		Reason: reason, State: "pending",
		RequestedByID: &u.ID, ApprovalMode: "manual_dual",
		TTLSeconds: ttl,
	}
	if err := h.db.Create(&req).Error; err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}
	detail := target
	if selfWarn && selfAck {
		// 把确认记进审计:事后复盘"谁把自己封了"时,这一行是唯一的证据。
		detail = fmt.Sprintf("%s self_ack=true from=%s", target, c.ClientIP())
	}
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "created", detail)

	if err := h.approvals.GenTokensAndSend(&req, &u.ID); err != nil {
		log.Printf("发送审批通知失败 req=%d: %v", req.ID, err)
	}

	c.Redirect(http.StatusFound, "/bans")
}

func (h *Handler) banApprove(c *gin.Context) {
	u := h.currentUser(c)

	h.decideMu.Lock()
	defer h.decideMu.Unlock()

	var req model.BanRequest
	if h.db.First(&req, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/bans")
		return
	}

	if req.State != "pending" {
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已处理,当前状态:" + req.State})
		return
	}

	now := time.Now()
	updates := map[string]any{
		"state":          "active",
		"approved_by_id": u.ID,
		"effective_at":   now,
	}
	if req.TTLSeconds != nil && *req.TTLSeconds > 0 {
		expires := now.Add(time.Duration(*req.TTLSeconds) * time.Second)
		updates["expires_at"] = expires
	}

	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&req, req.ID).Error; err != nil {
			return err
		}
		if req.State != "pending" {
			return errStateConflict
		}
		res := tx.Model(&req).Where("state = ?", "pending").Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errStateConflict
		}
		return nil
	})

	switch {
	case err == errStateConflict:
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已处理,当前状态:" + req.State})
		return
	case err != nil:
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}

	req.ApprovedByID = &u.ID
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "approved", "")

	if _, explain, err := h.dispatches().CreateDispatch(&req); err != nil {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": explain})
		return
	}

	h.recordLadder(req.Target)

	c.Redirect(http.StatusFound, "/bans")
}

func (h *Handler) banReject(c *gin.Context) {
	u := h.currentUser(c)

	h.decideMu.Lock()
	defer h.decideMu.Unlock()

	var req model.BanRequest
	if h.db.First(&req, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/bans")
		return
	}
	if req.State != "pending" {
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已处理,当前状态:" + req.State})
		return
	}
	res := h.db.Model(&req).Where("state = ?", "pending").Update("state", "rejected")
	if res.Error != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已处理"})
		return
	}
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "rejected", "")
	c.Redirect(http.StatusFound, "/bans")
}

func (h *Handler) banDetail(c *gin.Context) {
	u := h.currentUser(c)
	var req model.BanRequest
	if h.db.First(&req, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/bans")
		return
	}
	var approver model.User
	if req.ApprovedByID != nil {
		h.db.First(&approver, *req.ApprovedByID)
	}
	c.HTML(http.StatusOK, "ban_detail.html", gin.H{
		"u": u, "nav": navSections,
		"req": req, "approver": approver,
		"canApprove": req.State == "pending",
		"csrf":       h.csrfTokenFor(c),
	})
}

func (h *Handler) auditLog(c *gin.Context) {
	u := h.currentUser(c)
	var logs []model.AuditLog
	h.db.Order("occurred_at desc").Limit(500).Find(&logs)
	c.HTML(http.StatusOK, "audit.html", gin.H{
		"u": u, "nav": navSections, "logs": logs,
	})
}

// approveShow/approveDo 有意不接入 requireCSRF:该路径不在会话体系内(邮件里的一次性链接),
// 其防伪造性来自 token 本身不可猜测、一次性使用、且仅通过 URL 传递(不落 cookie)。
func (h *Handler) approveShow(c *gin.Context) {
	var token model.ApprovalToken
	if h.db.Where("token = ? AND expires_at > ? AND used_at IS NULL", c.Param("token"), time.Now()).First(&token).Error != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"msg": "审批链接已失效或已使用"})
		return
	}
	var req model.BanRequest
	h.db.First(&req, token.BanRequestID)
	c.HTML(http.StatusOK, "approve.html", gin.H{"token": token, "req": req})
}

func (h *Handler) approveDo(c *gin.Context) {
	action := c.PostForm("action")
	if action != "approve" && action != "reject" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "非法操作"})
		return
	}

	now := time.Now()
	var token model.ApprovalToken
	var req model.BanRequest

	h.decideMu.Lock()
	defer h.decideMu.Unlock()

	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("token = ? AND expires_at > ? AND used_at IS NULL",
			c.Param("token"), now).First(&token).Error; err != nil {
			return err
		}
		if err := tx.First(&req, token.BanRequestID).Error; err != nil {
			return err
		}
		if req.State != "pending" {
			return errStateConflict
		}

		if err := tx.Model(&token).Update("used_at", now).Error; err != nil {
			return err
		}

		if action == "approve" {
			updates := map[string]any{
				"state":              "active",
				"approved_by_id":     token.ApproverID,
				"approved_by_policy": "email_link",
				"effective_at":       now,
			}
			if req.TTLSeconds != nil && *req.TTLSeconds > 0 {
				updates["expires_at"] = now.Add(time.Duration(*req.TTLSeconds) * time.Second)
			}
			res := tx.Model(&req).Where("state = ?", "pending").Updates(updates)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return errStateConflict
			}
			return nil
		}
		res := tx.Model(&req).Where("state = ?", "pending").Update("state", "rejected")
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errStateConflict
		}
		return nil
	})

	switch {
	case err == errStateConflict:
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已被处理"})
		return
	case err != nil:
		c.HTML(http.StatusNotFound, "error.html", gin.H{"msg": "审批链接已失效或已使用"})
		return
	}

	actor := "approver:" + itoa(token.ApproverID)
	if action == "approve" {
		_ = model.WriteAudit(h.db, &token.ApproverID, actor, "BanRequest", itoa(req.ID), "approved_external", "")
		req.ApprovedByID = &token.ApproverID
		if _, explain, derr := h.dispatches().CreateDispatch(&req); derr != nil {
			c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": explain})
			return
		}
		h.recordLadder(req.Target)
	} else {
		_ = model.WriteAudit(h.db, &token.ApproverID, actor, "BanRequest", itoa(req.ID), "rejected_external", "")
	}

	c.HTML(http.StatusOK, "approve_done.html", gin.H{"action": action, "success": true})
}
