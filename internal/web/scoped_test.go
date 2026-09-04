package web

import (
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/prefixdb"
)

func TestParseHostTarget(t *testing.T) {
	ok := []struct{ in, want string }{
		{"10.0.1.100", "10.0.1.100"},
		{" 10.0.1.100 ", "10.0.1.100"},
		{"10.0.1.100/32", "10.0.1.100"},
	}
	for _, tc := range ok {
		got, err := parseHostTarget(tc.in)
		if err != nil {
			t.Errorf("parseHostTarget(%q) 报错: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHostTarget(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}

	bad := []struct{ in, why string }{
		{"", "空输入"},
		{"10.0.1.0/24", "网段目标必须拒绝"},
		{"10.0.0.0/8", "大网段更要拒绝"},
		{"10.0.1.100/31", "非 /32 前缀"},
		{"2001:db8::1", "IPv6 未支持"},
		{"not-an-ip", "非法格式"},
		{"999.1.1.1", "越界八位组"},
	}
	for _, tc := range bad {
		if _, err := parseHostTarget(tc.in); err == nil {
			t.Errorf("parseHostTarget(%q) 应报错(%s)", tc.in, tc.why)
		}
	}
}

func TestParseHostTarget_ErrorExplainsWhy(t *testing.T) {
	_, err := parseHostTarget("10.0.1.0/24")
	if err == nil {
		t.Fatal("应报错")
	}
	msg := err.Error()
	for _, kw := range []string{"/32", "LPM"} {
		if !contains(msg, kw) {
			t.Errorf("错误信息应提及 %q,实际: %s", kw, msg)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func newScopedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:scopedtest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{}, &model.AuditLog{}, &model.BanRequest{},
		&model.Dispatch{}, &model.ScopedBan{}, &model.ProtectedTarget{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM audit_logs")
	db.Exec("DELETE FROM ban_requests")
	db.Exec("DELETE FROM dispatches")
	db.Exec("DELETE FROM scoped_bans")
	db.Exec("DELETE FROM protected_targets")
	return db
}

func newScopedRouter(t *testing.T, db *gorm.DB, rv *fakeRevoker) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerTestRouter(r, db, rv)
	return r
}

func TestScopedBanCreate_GlobalSubmissionEndToEndCreatesOneDispatchPerCIDR(t *testing.T) {
	db := newScopedTestDB(t)
	mkUser(t, db, "admin", true)
	mkUser(t, db, "approver1", true)
	r := newScopedRouter(t, db, &fakeRevoker{})

	setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24", "203.0.113.0/24"}})

	sid := loginAs(t, r, "admin")
	w := postAs(t, r, sid, "/scoped", url.Values{
		"country": {"XX"}, "reason": {"test global ban"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("提交状态码 = %d, body=%s", w.Code, w.Body.String())
	}

	var sb model.ScopedBan
	if err := db.Order("id desc").First(&sb).Error; err != nil {
		t.Fatalf("未找到新建的范围封禁: %v", err)
	}
	if !sb.Global {
		t.Fatalf("未填目标主机应为全局封禁,Global = %v", sb.Global)
	}
	if sb.TargetIP != "" {
		t.Errorf("全局封禁的 TargetIP 应为空,实际 %q", sb.TargetIP)
	}

	sid2 := loginAs(t, r, "approver1")
	w2 := postAs(t, r, sid2, "/scoped/"+itoa(sb.ID)+"/approve", nil)
	if w2.Code != http.StatusFound {
		t.Fatalf("批准状态码 = %d, body=%s", w2.Code, w2.Body.String())
	}

	var dispatches []model.Dispatch
	db.Where("ban_id LIKE ?", "scoped-global-%").Find(&dispatches)
	if len(dispatches) != 2 {
		t.Errorf("dispatch 数量 = %d, 期望 2(每条解析 CIDR 一条)", len(dispatches))
	}

	var reloaded model.ScopedBan
	db.First(&reloaded, sb.ID)
	if reloaded.State != "active" {
		t.Errorf("批准后 state = %q, 期望 active", reloaded.State)
	}
}

func TestScopedBanCreate_GlobalSubmissionRejectedWhenOverlapsProtectedTarget(t *testing.T) {
	db := newScopedTestDB(t)
	mkUser(t, db, "admin", true)
	r := newScopedRouter(t, db, &fakeRevoker{})

	db.Create(&model.ProtectedTarget{Target: "198.51.100.55", Active: true})

	setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})

	sid := loginAs(t, r, "admin")
	w := postAs(t, r, sid, "/scoped", url.Values{
		"country": {"XX"}, "reason": {"test global ban"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("命中保护集时状态码 = %d, 期望 400, body=%s", w.Code, w.Body.String())
	}

	var count int64
	db.Model(&model.ScopedBan{}).Count(&count)
	if count != 0 {
		t.Errorf("命中保护集的全局提交不应落库,实际 %d 条", count)
	}
}

func TestScopedPreview_CloudASNSelectorReturnsWarningWithoutBlocking(t *testing.T) {
	db := newScopedTestDB(t)
	mkUser(t, db, "admin", true)
	r := newScopedRouter(t, db, &fakeRevoker{})

	setTestPrefixASN(t, 16509, "XX", []string{"198.51.100.0/24"})

	sid := loginAs(t, r, "admin")
	w := postAs(t, r, sid, "/scoped/preview", url.Values{"asn": {"16509"}})
	if w.Code != http.StatusOK {
		t.Fatalf("预览状态码 = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !contains(body, "cloud_warning") {
		t.Errorf("命中云服务商 ASN 应返回 cloud_warning 字段,实际: %s", body)
	}
	if !contains(body, `"allowed":true`) {
		t.Errorf("云服务商警告不应阻止提交(allowed 应为 true),实际: %s", body)
	}
}

func setTestPrefixDB(t *testing.T, byCountry map[string][]string) {
	t.Helper()

	prev := prefixdb.Global()
	t.Cleanup(func() { prefixdb.SetGlobal(prev) })

	entries := make([]prefixdb.Entry, 0)
	idxByCountry := make(map[string][]int)
	for country, cidrs := range byCountry {
		for _, c := range cidrs {
			start, end := cidrRangeForTest(t, c)

			idx := len(entries)
			entries = append(entries, prefixdb.Entry{Start: start, End: end, Country: country})
			idxByCountry[country] = append(idxByCountry[country], idx)
		}
	}

	db := prefixdb.NewForTest(entries, idxByCountry, nil)
	prefixdb.SetGlobal(db)
}

func setTestPrefixASN(t *testing.T, asn uint32, country string, cidrs []string) {
	t.Helper()

	prev := prefixdb.Global()
	t.Cleanup(func() { prefixdb.SetGlobal(prev) })

	entries := make([]prefixdb.Entry, 0)
	idxByASN := make(map[uint32][]int)
	for _, c := range cidrs {
		start, end := cidrRangeForTest(t, c)

		idx := len(entries)
		entries = append(entries, prefixdb.Entry{Start: start, End: end, Country: country, ASN: asn})
		idxByASN[asn] = append(idxByASN[asn], idx)
	}

	db := prefixdb.NewForTest(entries, nil, idxByASN)
	prefixdb.SetGlobal(db)
}

func cidrRangeForTest(t *testing.T, cidr string) (uint32, uint32) {
	t.Helper()
	p := netip.MustParsePrefix(cidr)
	b := p.Masked().Addr().As4()
	start := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	end := start + (uint32(1)<<(32-p.Bits()) - 1)
	return start, end
}
