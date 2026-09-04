package web

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
)

const minPasswordLen = 8

// 这里曾经是一整套「用户管理」:新建用户、改角色、停用/启用、删除,外加
// "不能降级最后一个 admin""不能停用自己"这类互锁。那套东西的前提是有多个
// 账号需要互相约束;这个工具是一个人自己用的,只有一个 admin,于是全部互锁
// 保护的都是不存在的情况。
//
// 剩下的只有一件真正必须能做的事:改掉 README 里公开写着的初始口令。
func (h *Handler) accountPage(c *gin.Context) {
	h.renderAccount(c, http.StatusOK, "", "")
}

func (h *Handler) renderAccount(c *gin.Context, code int, errMsg, okMsg string) {
	u := h.currentUser(c)
	c.HTML(code, "account.html", gin.H{
		"u": u, "nav": navSections,
		"err":  errMsg,
		"ok":   okMsg,
		"csrf": h.csrfTokenFor(c),
	})
}

func (h *Handler) accountChangePassword(c *gin.Context) {
	u := h.currentUser(c)

	// 校验当前口令:cookie 被人拿到时,这一步让对方至少改不掉密码把你锁在外面。
	if !u.CheckPassword(c.PostForm("current")) {
		h.renderAccount(c, http.StatusUnauthorized, "当前密码不正确", "")
		return
	}

	newPwd := c.PostForm("password")
	if len(newPwd) < minPasswordLen {
		h.renderAccount(c, http.StatusBadRequest,
			fmt.Sprintf("新密码至少 %d 位", minPasswordLen), "")
		return
	}
	if newPwd != c.PostForm("confirm") {
		h.renderAccount(c, http.StatusBadRequest, "两次输入的新密码不一致", "")
		return
	}
	if newPwd == c.PostForm("current") {
		h.renderAccount(c, http.StatusBadRequest, "新密码与当前密码相同", "")
		return
	}

	if err := u.SetPassword(newPwd); err != nil {
		h.renderAccount(c, http.StatusInternalServerError, err.Error(), "")
		return
	}
	if err := h.db.Model(u).Update("password_hash", u.PasswordHash).Error; err != nil {
		h.renderAccount(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "User", itoa(u.ID),
		"password_changed", u.Username)

	// 吊销全部会话(含当前这一个)——改密码的常见动机就是怀疑旧会话已泄露。
	h.sessions.DeleteByUser(u.ID)
	c.SetCookie("sid", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login")
}
