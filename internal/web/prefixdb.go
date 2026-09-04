package web

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/prefixdb"
)

const maxUploadSize = 256 << 20

func (h *Handler) prefixDBPage(c *gin.Context) {
	u := h.currentUser(c)

	data := gin.H{
		"u": u, "nav": navSections,
		"sources":      prefixdb.Sources,
		"syncStatus":   prefixdb.Status(),
		"dataDir":      prefixdb.DataDir(),
		"overridePath": prefixdb.OverridePath(),
	}
	if db := prefixdb.Global(); db != nil {
		data["stats"] = db.Stats()
	}

	if b, err := os.ReadFile(prefixdb.OverridePath()); err == nil {
		data["overrideText"] = string(b)
	}
	data["csrf"] = h.csrfTokenFor(c)
	c.HTML(http.StatusOK, "prefixdb.html", data)
}

func (h *Handler) prefixDBSync(c *gin.Context) {
	u := h.currentUser(c)

	src, ok := prefixdb.SourceByID(c.PostForm("source"))
	if !ok {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "未知数据源"})
		return
	}

	go func() {
		if err := prefixdb.SyncFrom(src); err != nil {
			_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", src.ID,
				"sync_failed", err.Error())
			return
		}
		detail := ""
		if db := prefixdb.Global(); db != nil {
			st := db.Stats()
			detail = fmt.Sprintf("entries=%d countries=%d asns=%d",
				st.Entries, st.Countries, st.ASNs)
		}
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", src.ID, "synced", detail)
	}()

	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", src.ID, "sync_started", src.URL)
	c.Redirect(http.StatusFound, "/prefixdb")
}

func (h *Handler) prefixDBStatus(c *gin.Context) {
	st := prefixdb.Status()
	resp := gin.H{
		"in_progress": st.InProgress,
		"source":      st.SourceID,
		"bytes":       st.BytesRead,
		"entries":     st.Entries,
		"error":       st.Err,
	}
	if db := prefixdb.Global(); db != nil {
		s := db.Stats()
		resp["loaded_entries"] = s.Entries
		resp["loaded_at"] = s.LoadedAt
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) prefixDBUpload(c *gin.Context) {
	u := h.currentUser(c)

	fh, err := c.FormFile("dbfile")
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "请选择要上传的文件"})
		return
	}
	if fh.Size > maxUploadSize {
		c.HTML(http.StatusRequestEntityTooLarge, "error.html", gin.H{
			"msg": fmt.Sprintf("文件过大(%.1f MB),上限 %d MB",
				float64(fh.Size)/(1<<20), maxUploadSize>>20)})
		return
	}

	format := c.PostForm("format")
	if format == "" {
		format = "ip2asn_tsv"
	}

	f, err := fh.Open()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}
	defer f.Close()

	n, err := prefixdb.ImportUpload(f, format)
	if err != nil {
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", "upload",
			"upload_failed", err.Error())
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": err.Error()})
		return
	}

	detail := fmt.Sprintf("file=%s size=%d format=%s entries=%d",
		fh.Filename, fh.Size, format, n)
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", "upload", "uploaded", detail)
	c.Redirect(http.StatusFound, "/prefixdb")
}

func (h *Handler) prefixDBSaveOverride(c *gin.Context) {
	u := h.currentUser(c)
	text := c.PostForm("overrides")

	if err := prefixdb.ValidateOverrides(strings.NewReader(text)); err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"msg": "本地规则格式有误,未保存:" + err.Error()})
		return
	}

	if err := os.MkdirAll(prefixdb.DataDir(), 0o755); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}
	if err := os.WriteFile(prefixdb.OverridePath(), []byte(text), 0o644); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}

	reloadNote := ""
	if err := prefixdb.Reload(); err != nil {
		reloadNote = " (主库尚未导入,规则将在导入后生效)"
	}

	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", "overrides",
		"overrides_saved", fmt.Sprintf("bytes=%d%s", len(text), reloadNote))
	c.Redirect(http.StatusFound, "/prefixdb")
}
