package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

// testHandlers 记住每个测试路由对应的 Handler,好让 postAs 能从会话里取出
// CSRF token 自动补上。测试关心的是被测路由本身的行为,不该每处都手写 token;
// CSRF 中间件本身由 csrf_test.go 专门覆盖。
var testHandlers sync.Map // *gin.Engine -> *Handler

func registerTestRouter(r *gin.Engine, db *gorm.DB, rv Revoker) {
	testHandlers.Store(r, Register(r, db, rv))
}

// csrfTokenForTest 取会话里的 CSRF token;取不到就返回空串,
// 让请求照原样发出去(缺 token 的负例测试依赖这一点)。
func csrfTokenForTest(r *gin.Engine, sid string) string {
	v, ok := testHandlers.Load(r)
	if !ok {
		return ""
	}
	tok, _ := v.(*Handler).sessions.CSRFToken(sid)
	return tok
}

func newWebTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:webtest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM audit_logs")
	return db
}

func mkUser(t *testing.T, db *gorm.DB, name string, active bool) *model.User {
	t.Helper()
	u := &model.User{Username: name, Active: active}
	if err := u.SetPassword("password123"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	return u
}

func loginAs(t *testing.T, r *gin.Engine, username string) string {
	t.Helper()
	body := strings.NewReader("username=" + username + "&password=password123")
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	for _, c := range w.Result().Cookies() {
		if c.Name == "sid" {
			return c.Value
		}
	}
	t.Fatalf("登录 %s 未获得 sid(状态码 %d)", username, w.Code)
	return ""
}

func postAs(t *testing.T, r *gin.Engine, sid, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	// 复制一份再改,避免污染调用方传进来的 url.Values。
	body := url.Values{}
	for k, vs := range form {
		body[k] = append([]string(nil), vs...)
	}
	if body.Get("csrf_token") == "" {
		if tok := csrfTokenForTest(r, sid); tok != "" {
			body.Set("csrf_token", tok)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func getAs(t *testing.T, r *gin.Engine, sid, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func newWebRouter(t *testing.T, db *gorm.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerTestRouter(r, db, &fakeRevoker{})
	return r
}
