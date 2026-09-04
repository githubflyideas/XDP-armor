package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

func newAuthTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:sesstest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM users")

	u := &model.User{Username: "admin", Active: true}
	_ = u.SetPassword("admin12345")
	db.Create(u)
	return db
}

func TestSessionStore_ConcurrentLoginAndAccess(t *testing.T) {
	db := newAuthTestDB(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r, db, &fakeRevoker{})

	var wg sync.WaitGroup

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := strings.NewReader("username=admin&password=admin12345")
			req := httptest.NewRequest(http.MethodPost, "/login", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusFound {
				t.Errorf("登录状态码 = %d, 期望 302", w.Code)
			}
		}()
	}

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
			req.AddCookie(&http.Cookie{Name: "sid", Value: "bogus-token"})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusFound {
				t.Errorf("未授权访问状态码 = %d, 期望 302", w.Code)
			}
		}()
	}

	wg.Wait()
}

func TestSessionStore_LogoutRevokes(t *testing.T) {
	db := newAuthTestDB(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r, db, &fakeRevoker{})

	body := strings.NewReader("username=admin&password=admin12345")
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var sid string
	for _, c := range w.Result().Cookies() {
		if c.Name == "sid" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("登录未下发 sid cookie")
	}

	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("登录后访问 dashboard = %d, 期望 200", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("登出后仍可访问 dashboard(状态码 %d),会话未吊销", w.Code)
	}
}
