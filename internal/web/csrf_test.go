package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRF_MissingTokenRejected(t *testing.T) {
	db := newWebTestDB(t)
	mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	req := httptest.NewRequest(http.MethodPost, "/account/password", strings.NewReader(
		url.Values{"current": {"password123"}, "password": {"newsecret123"},
			"confirm": {"newsecret123"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("缺 csrf_token 的 POST 状态码 = %d, 期望 403", w.Code)
	}
}

func TestCSRF_WrongTokenRejected(t *testing.T) {
	db := newWebTestDB(t)
	mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/account/password", url.Values{
		"current": {"password123"}, "password": {"newsecret123"}, "confirm": {"newsecret123"},
		"csrf_token": {"totally-wrong-token"},
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("错误 csrf_token 的 POST 状态码 = %d, 期望 403", w.Code)
	}
}

func TestCSRF_CorrectTokenFromSessionPasses(t *testing.T) {
	db := newWebTestDB(t)
	mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	body := getAs(t, r, sid, "/account").Body.String()
	tok := extractCSRFToken(t, body)

	w := postAs(t, r, sid, "/account/password", url.Values{
		"current": {"password123"}, "password": {"newsecret123"}, "confirm": {"newsecret123"},
		"csrf_token": {tok},
	})
	// 改密成功后吊销全部会话并跳登录页,所以是 302 而不是 200。
	if w.Code != http.StatusFound {
		t.Errorf("正确 csrf_token 的 POST 状态码 = %d, 期望 302, body=%s", w.Code, w.Body.String())
	}
}

func TestCSRF_GETRoutesUnaffected(t *testing.T) {
	db := newWebTestDB(t)
	mkUser(t, db, "admin", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "admin")

	if code := getAs(t, r, sid, "/account").Code; code != http.StatusOK {
		t.Errorf("GET /account = %d, 期望 200(GET 不受 CSRF 中间件约束)", code)
	}
	if code := getAs(t, r, sid, "/dashboard").Code; code != http.StatusOK {
		t.Errorf("GET /dashboard = %d, 期望 200", code)
	}
}

// /approve/:token 故意不接入 requireCSRF——该路径不在会话体系内(邮件里的一次性链接),
// 防伪造性来自 token 本身不可猜测、一次性使用、且只经 URL 传递,不落 cookie。
// 这里不测试该路径受 CSRF 中间件保护(它本就不该受保护),只是记录这一设计决定。
func TestCSRF_ApproveLinkPathIsIntentionallyExempt(t *testing.T) {
	t.Skip("/approve/:token 设计上不接入 requireCSRF,见 handlers.go 中的注释")
}

func extractCSRFToken(t *testing.T, html string) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	i := strings.Index(html, marker)
	if i == -1 {
		t.Fatalf("页面中未找到 csrf_token 隐藏字段")
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j == -1 {
		t.Fatalf("csrf_token 字段格式异常")
	}
	return rest[:j]
}
