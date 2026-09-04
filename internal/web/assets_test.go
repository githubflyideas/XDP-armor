package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFavicon_ServedFromBinaryWithoutLogin 钉住"单文件部署"这条线:
// 图标必须从二进制里出来,不依赖进程工作目录下有没有 favicon.ico。
// 这个路由在 auth 组外,不需要登录也不需要 CSRF token。
func TestFavicon_ServedFromBinaryWithoutLogin(t *testing.T) {
	db := newWebTestDB(t)
	r := newWebRouter(t, db)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("favicon 状态码 = %d, 期望 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/x-icon" {
		t.Errorf("Content-Type = %q, 期望 image/x-icon", ct)
	}

	body := w.Body.Bytes()
	if len(body) == 0 {
		t.Fatal("favicon 内容为空")
	}
	// ICONDIR 头:reserved=0, type=1(icon), count>=1。
	if len(body) < 6 || body[0] != 0 || body[1] != 0 || body[2] != 1 || body[3] != 0 {
		t.Errorf("不是合法的 ICO 头: % x", body[:min(6, len(body))])
	}
	if got := int(body[4]) | int(body[5])<<8; got < 1 {
		t.Errorf("ICO 图像数 = %d, 期望至少 1", got)
	}
}
