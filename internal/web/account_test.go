package web

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/xdpban/xdp-ban/internal/model"
)

func TestAccountChangePassword_WrongCurrentRejected(t *testing.T) {
	db := newWebTestDB(t)
	u := mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/account/password", url.Values{
		"current": {"not-the-password"}, "password": {"newsecret123"},
		"confirm": {"newsecret123"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("状态码 = %d, 期望 401", w.Code)
	}

	var got model.User
	db.First(&got, u.ID)
	if !got.CheckPassword("password123") {
		t.Error("当前密码校验失败时密码仍被改掉了")
	}
}

func TestAccountChangePassword_MismatchAndTooShortRejected(t *testing.T) {
	db := newWebTestDB(t)
	u := mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	for _, tc := range []struct {
		name string
		form url.Values
	}{
		{"两次不一致", url.Values{"current": {"password123"},
			"password": {"newsecret123"}, "confirm": {"newsecret124"}}},
		{"太短", url.Values{"current": {"password123"},
			"password": {"short"}, "confirm": {"short"}}},
		{"与原密码相同", url.Values{"current": {"password123"},
			"password": {"password123"}, "confirm": {"password123"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := postAs(t, r, sid, "/account/password", tc.form).Code; code != http.StatusBadRequest {
				t.Errorf("状态码 = %d, 期望 400", code)
			}
		})
	}

	var got model.User
	db.First(&got, u.ID)
	if !got.CheckPassword("password123") {
		t.Error("被拒绝的请求改掉了密码")
	}
}

// 改密成功后旧会话必须失效 —— 改密码的常见动机就是怀疑 cookie 已泄露,
// 如果旧 sid 还能用,那这个动作就没有意义。
func TestAccountChangePassword_RevokesSessions(t *testing.T) {
	db := newWebTestDB(t)
	u := mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/account/password", url.Values{
		"current": {"password123"}, "password": {"newsecret123"},
		"confirm": {"newsecret123"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("状态码 = %d, 期望 302, body=%s", w.Code, w.Body.String())
	}

	var got model.User
	db.First(&got, u.ID)
	if !got.CheckPassword("newsecret123") {
		t.Fatal("新密码未生效")
	}

	if code := getAs(t, r, sid, "/account").Code; code != http.StatusFound {
		t.Errorf("改密后旧 sid 访问 /account = %d, 期望 302 跳登录", code)
	}
}

// 用户管理整套路由已删掉,不该还能访问。
func TestUsersRoutesGone(t *testing.T) {
	db := newWebTestDB(t)
	mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	for _, p := range []string{"/users", "/users/1/role", "/users/1/toggle", "/users/1/delete"} {
		if code := getAs(t, r, sid, p).Code; code != http.StatusNotFound {
			t.Errorf("GET %s = %d, 期望 404", p, code)
		}
	}
}
