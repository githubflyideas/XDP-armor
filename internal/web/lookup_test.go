package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

func newLookupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:lookuptest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{}, &model.AuditLog{}, &model.BanRequest{},
		&model.Dispatch{}, &model.ScopedBan{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM audit_logs")
	db.Exec("DELETE FROM ban_requests")
	db.Exec("DELETE FROM dispatches")
	db.Exec("DELETE FROM scoped_bans")
	return db
}

func newLookupRouter(t *testing.T, db *gorm.DB, rv *fakeRevoker) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerTestRouter(r, db, rv)
	return r
}

func TestLookupSearch_FindsActiveGlobalBan(t *testing.T) {
	db := newLookupTestDB(t)
	mkUser(t, db, "admin", true)
	r := newLookupRouter(t, db, &fakeRevoker{})
	sid := loginAs(t, r, "admin")

	req := model.BanRequest{
		ActionType: "ban", Target: "203.0.113.7", Source: "manual",
		State: "active", Reason: "测试",
	}
	if err := db.Create(&req).Error; err != nil {
		t.Fatalf("create ban request: %v", err)
	}

	w := postAs(t, r, sid, "/lookup", url.Values{"ip": {"203.0.113.7"}})
	if w.Code != http.StatusOK {
		t.Fatalf("查询状态码 = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.7") {
		t.Errorf("查询结果未包含目标 IP: %s", body)
	}
	if strings.Contains(body, "未发现覆盖") {
		t.Errorf("应命中活跃全局封禁,却显示未命中: %s", body)
	}
}

func TestLookupSearch_FindsActiveScopedBanByResolvedCIDR(t *testing.T) {
	db := newLookupTestDB(t)
	mkUser(t, db, "admin", true)
	r := newLookupRouter(t, db, &fakeRevoker{})
	sid := loginAs(t, r, "admin")

	sb := model.ScopedBan{
		TargetIP: "10.0.1.100", Country: "XX", PrefixCount: 1,
		AddressCount: 256, State: "active",
	}
	if err := db.Create(&sb).Error; err != nil {
		t.Fatalf("create scoped ban: %v", err)
	}

	setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})

	w := postAs(t, r, sid, "/lookup", url.Values{"ip": {"198.51.100.55"}})
	if w.Code != http.StatusOK {
		t.Fatalf("查询状态码 = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "未发现覆盖") {
		t.Errorf("应命中活跃范围封禁的解析 CIDR,却显示未命中: %s", body)
	}
}

func TestLookupSearch_CleanIPReturnsNoMatch(t *testing.T) {
	db := newLookupTestDB(t)
	mkUser(t, db, "admin", true)
	r := newLookupRouter(t, db, &fakeRevoker{})
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/lookup", url.Values{"ip": {"192.0.2.55"}})
	if w.Code != http.StatusOK {
		t.Fatalf("查询状态码 = %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "未发现覆盖") {
		t.Errorf("干净 IP 应无命中,实际: %s", w.Body.String())
	}
}

func TestLookupRollback_ActiveGlobalBanCallsRevokeGlobalAndTransitionsState(t *testing.T) {
	db := newLookupTestDB(t)
	mkUser(t, db, "admin", true)
	rv := &fakeRevoker{}
	r := newLookupRouter(t, db, rv)
	sid := loginAs(t, r, "admin")

	req := model.BanRequest{
		ActionType: "ban", Target: "203.0.113.7", Source: "manual", State: "active",
	}
	db.Create(&req)

	w := postAs(t, r, sid, "/lookup/ban/"+itoa(req.ID)+"/rollback", nil)
	if w.Code != http.StatusFound {
		t.Fatalf("回滚状态码 = %d, body=%s", w.Code, w.Body.String())
	}

	if len(rv.globalCalls) != 1 || rv.globalCalls[0] != "203.0.113.7" {
		t.Errorf("RevokeGlobal 调用 = %v, 期望 [203.0.113.7]", rv.globalCalls)
	}

	var reloaded model.BanRequest
	db.First(&reloaded, req.ID)
	if reloaded.State != "revoked" {
		t.Errorf("state = %q, 期望 revoked", reloaded.State)
	}
	if reloaded.ClearedAt == nil {
		t.Error("cleared_at 未设置")
	}
}

// 回滚曾经挂 requireCap(UnbanExecute),viewer 会拿到 403。角色矩阵移除后,
// 唯一的闸门是"登录了没有" —— 这里改成钉住这条:没会话的回滚请求必须被挡在门外
// 且不改状态。真要分权,交给前面的反向代理。
func TestLookupRollback_RequiresLogin(t *testing.T) {
	db := newLookupTestDB(t)
	mkUser(t, db, "admin", true)
	r := newLookupRouter(t, db, &fakeRevoker{})

	req := model.BanRequest{
		ActionType: "ban", Target: "203.0.113.7", Source: "manual", State: "active",
	}
	db.Create(&req)

	w := postAs(t, r, "no-such-session", "/lookup/ban/"+itoa(req.ID)+"/rollback", nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("未登录回滚 = %d Location=%q, 期望 302 → /login",
			w.Code, w.Header().Get("Location"))
	}

	var reloaded model.BanRequest
	db.First(&reloaded, req.ID)
	if reloaded.State != "active" {
		t.Errorf("未登录的回滚请求不应改变状态,实际 = %q", reloaded.State)
	}
}

func TestLookupRollback_PendingBanIsRejectedNotRevoked(t *testing.T) {
	db := newLookupTestDB(t)
	mkUser(t, db, "admin", true)
	rv := &fakeRevoker{}
	r := newLookupRouter(t, db, rv)
	sid := loginAs(t, r, "admin")

	req := model.BanRequest{
		ActionType: "ban", Target: "203.0.113.7", Source: "manual", State: "pending",
	}
	db.Create(&req)

	w := postAs(t, r, sid, "/lookup/ban/"+itoa(req.ID)+"/rollback", nil)
	if w.Code != http.StatusFound {
		t.Fatalf("回滚状态码 = %d", w.Code)
	}
	if len(rv.globalCalls) != 0 {
		t.Errorf("pending 状态不应调用 RevokeGlobal(尚未下发),实际调用 %v", rv.globalCalls)
	}

	var reloaded model.BanRequest
	db.First(&reloaded, req.ID)
	if reloaded.State != "rejected" {
		t.Errorf("state = %q, 期望 rejected", reloaded.State)
	}
}

func TestLookupRollback_ActiveScopedGlobalBanRevokesAllResolvedPrefixes(t *testing.T) {
	db := newLookupTestDB(t)
	mkUser(t, db, "admin", true)
	rv := &fakeRevoker{}
	r := newLookupRouter(t, db, rv)
	sid := loginAs(t, r, "admin")

	sb := model.ScopedBan{
		Global: true, Country: "XX", PrefixCount: 2, AddressCount: 512, State: "active",
	}
	db.Create(&sb)

	for _, prefix := range []string{"198.51.100.0/24", "203.0.113.0/24"} {
		payload := `{"target":"` + prefix + `"}`
		db.Create(&model.Dispatch{
			BanRequestID: sb.ID,
			BanID:        "scoped-global-" + itoa(sb.ID) + "-" + prefix,
			Payload:      payload,
			State:        "acked",
		})
	}

	w := postAs(t, r, sid, "/lookup/scoped/"+itoa(sb.ID)+"/rollback", nil)
	if w.Code != http.StatusFound {
		t.Fatalf("回滚状态码 = %d, body=%s", w.Code, w.Body.String())
	}

	if len(rv.globalCalls) != 2 {
		t.Errorf("RevokeGlobal 调用次数 = %d, 期望 2(每个已解析 CIDR 一次)", len(rv.globalCalls))
	}

	var reloaded model.ScopedBan
	db.First(&reloaded, sb.ID)
	if reloaded.State != "revoked" {
		t.Errorf("state = %q, 期望 revoked", reloaded.State)
	}
}
