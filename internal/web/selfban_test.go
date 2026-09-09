package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
)

// 自封检查的价值全在"提交前拦一次"。这组测试盯三件事:
//  1. 覆盖了自己的地址必须先拦下来,别默默生效;
//  2. 勾了确认要能真的提交上去 —— 表单回填一旦漏了 csrf,这条路就是死的;
//  3. 没覆盖自己的正常提交不受影响。

func newSelfBanDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newWebTestDB(t)
	if err := db.AutoMigrate(&model.BanRequest{}, &model.Dispatch{},
		&model.ProtectedTarget{}, &model.BanLadder{}, &model.ScopedBan{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, tbl := range []string{"ban_requests", "dispatches", "protected_targets",
		"ban_ladders", "scoped_bans"} {
		db.Exec("DELETE FROM " + tbl)
	}
	return db
}

// postFrom 与 postAs 相同,只是额外伪造 X-Forwarded-For —— 那正是 c.ClientIP()
// 会读的头,也是"操作者自己的地址"在有反代时的唯一来源。
func postFrom(t *testing.T, r *gin.Engine, sid, clientIP, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
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
	req.Header.Set("X-Forwarded-For", clientIP)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestBanCreate_CoveringOwnIPIsBlockedUntilAcked(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "op")

	form := url.Values{"target": {"203.0.113.0/24"}, "reason": {"ssh 爆破"}}
	w := postFrom(t, r, sid, "203.0.113.9", "/bans", form)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 %d,期望 400 —— 封住自己所在的 /24 必须先拦一次", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.9") || !strings.Contains(body, "203.0.113.0/24") {
		t.Errorf("提示里应同时点明操作者地址和命中的前缀:\n%s", body)
	}
	if !strings.Contains(body, "xdp-ban why") || !strings.Contains(body, "iptables") {
		t.Errorf("提示必须给出控制台补救路径,并说明 iptables 里看不到:\n%s", body)
	}
	if !strings.Contains(body, `name="self_ack"`) {
		t.Errorf("必须把确认复选框渲染出来,否则用户无处可勾:\n%s", body)
	}

	var n int64
	db.Model(&model.BanRequest{}).Count(&n)
	if n != 0 {
		t.Errorf("被拦下的提交不应留下 BanRequest,实际 %d 条", n)
	}
}

// 这条是整个 C 部分能不能用的关键。之前 banCreate 的错误分支不回填 csrf,
// 重渲染出来的表单 token 是空的 —— 用户勾上确认再提交只会吃 403,
// 也就是说"勾选后重新提交"这条路根本走不通。
func TestBanCreate_ErrorRerenderKeepsCSRFAndInputs(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "op")

	form := url.Values{"target": {"203.0.113.0/24"}, "reason": {"ssh 爆破"}}
	body := postFrom(t, r, sid, "203.0.113.9", "/bans", form).Body.String()

	tok := csrfTokenForTest(r, sid)
	if tok == "" {
		t.Fatal("测试前提不成立:取不到会话 CSRF token")
	}
	if !strings.Contains(body, tok) {
		t.Errorf("重渲染的表单缺少 csrf_token,勾选确认后重新提交会吃 403:\n%s", body)
	}
	if !strings.Contains(body, `value="203.0.113.0/24"`) {
		t.Errorf("重渲染应回填目标:\n%s", body)
	}
	if !strings.Contains(body, "ssh 爆破") {
		t.Errorf("重渲染应回填原因:\n%s", body)
	}
}

func TestBanCreate_AckedSubmissionGoesThroughAndIsAudited(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "op")

	form := url.Values{
		"target": {"203.0.113.0/24"}, "reason": {"ssh 爆破"},
		"self_ack": {"1"},
	}
	w := postFrom(t, r, sid, "203.0.113.9", "/bans", form)
	if w.Code != http.StatusFound {
		t.Fatalf("状态码 %d,期望 302 —— 勾了确认就该放行(这是防手滑,不是权限)", w.Code)
	}

	var req model.BanRequest
	if err := db.Where("target = ?", "203.0.113.0/24").First(&req).Error; err != nil {
		t.Fatalf("确认后应落库: %v", err)
	}

	var logs []model.AuditLog
	db.Where("entity_type = ? AND event = ?", "BanRequest", "created").Find(&logs)
	found := false
	for _, l := range logs {
		if strings.Contains(l.Detail, "self_ack=true") && strings.Contains(l.Detail, "203.0.113.9") {
			found = true
		}
	}
	if !found {
		t.Errorf("审计里必须留下 self_ack 和来源地址 —— 事后复盘'谁把自己封了'只有这一行证据,实际 %+v", logs)
	}
}

func TestBanCreate_UnrelatedTargetIsUnaffected(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "op")

	form := url.Values{"target": {"198.51.100.0/24"}, "reason": {"扫描"}}
	w := postFrom(t, r, sid, "203.0.113.9", "/bans", form)
	if w.Code != http.StatusFound {
		t.Fatalf("状态码 %d,期望 302 —— 与操作者无关的前缀不该被这个检查挡住", w.Code)
	}

	var logs []model.AuditLog
	db.Where("entity_type = ?", "BanRequest").Find(&logs)
	for _, l := range logs {
		if strings.Contains(l.Detail, "self_ack") {
			t.Errorf("没触发自封检查时不该往审计里写 self_ack: %q", l.Detail)
		}
	}
}

// 单个 /32 也要覆盖:最直白的自封方式就是照着自己的地址封一条。
func TestBanCreate_ExactOwnAddressIsBlocked(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "op")

	form := url.Values{"target": {"203.0.113.9"}, "reason": {"手滑"}}
	if code := postFrom(t, r, sid, "203.0.113.9", "/bans", form).Code; code != http.StatusBadRequest {
		t.Errorf("状态码 %d,期望 400", code)
	}
}

// 保护集的否决是终局的,不该被自封的"再确认一次"顶掉 —— 顺序不能反。
func TestBanCreate_ProtectedTargetStillVetoedEvenWithAck(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	sid := loginAs(t, r, "op")

	form := url.Values{
		"target": {"127.0.0.1"}, "reason": {"手滑"}, "self_ack": {"1"},
	}
	w := postFrom(t, r, sid, "127.0.0.1", "/bans", form)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 %d,期望 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SAFETY VETO") {
		t.Errorf("应报保护集否决,而不是自封提示:\n%s", w.Body.String())
	}

	var n int64
	db.Model(&model.BanRequest{}).Count(&n)
	if n != 0 {
		t.Errorf("硬保护集命中时不该落库,实际 %d 条", n)
	}
}

// 按国家/AS 提交时没人会去逐条核对解析出来的几百条前缀里有没有自己 ——
// 这正是自封检查在 scoped 路径上比在单目标路径上更有价值的原因。
func TestScopedBanCreate_GlobalScopeCoveringOwnIPIsBlockedUntilAcked(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	setTestPrefixDB(t, map[string][]string{"XX": {"203.0.113.0/24"}})
	sid := loginAs(t, r, "op")

	form := url.Values{"country": {"XX"}, "reason": {"整段都在扫"}}
	w := postFrom(t, r, sid, "203.0.113.9", "/scoped", form)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 %d,期望 400 —— XX 解析出的前缀覆盖了操作者自己", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.9") || !strings.Contains(body, "203.0.113.0/24") {
		t.Errorf("提示应点明操作者地址和命中的前缀:\n%s", body)
	}
	if !strings.Contains(body, `name="self_ack"`) {
		t.Errorf("scoped 表单也必须渲染确认复选框:\n%s", body)
	}
	// 勾选后重新提交要能带着原来的选择 —— 否则得重选国家、重跑一次预览。
	if !strings.Contains(body, `value="XX" selected`) {
		t.Errorf("重渲染应把选中的国家保留下来:\n%s", body)
	}
	if !strings.Contains(body, "整段都在扫") {
		t.Errorf("重渲染应回填原因:\n%s", body)
	}

	var n int64
	db.Model(&model.ScopedBan{}).Count(&n)
	if n != 0 {
		t.Errorf("被拦下的提交不应落库,实际 %d 条", n)
	}
}

func TestScopedBanCreate_AckedGlobalScopeGoesThroughAndIsAudited(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	setTestPrefixDB(t, map[string][]string{"XX": {"203.0.113.0/24"}})
	sid := loginAs(t, r, "op")

	form := url.Values{"country": {"XX"}, "reason": {"整段都在扫"}, "self_ack": {"1"}}
	w := postFrom(t, r, sid, "203.0.113.9", "/scoped", form)
	if w.Code != http.StatusFound {
		t.Fatalf("状态码 %d,期望 302,body=%s", w.Code, w.Body.String())
	}

	var logs []model.AuditLog
	db.Where("entity_type = ? AND event = ?", "ScopedBan", "created").Find(&logs)
	found := false
	for _, l := range logs {
		if strings.Contains(l.Detail, "self_ack=true") && strings.Contains(l.Detail, "203.0.113.9") {
			found = true
		}
	}
	if !found {
		t.Errorf("审计里必须留下 self_ack 和来源地址,实际 %+v", logs)
	}
}

// 定向封禁只切断"到某台主机"的流量,提示措辞必须不同 —— 否则操作者会以为
// 自己要整体掉线,该做的操作被一句过重的警告吓停。
func TestScopedBanCreate_PerTargetScopeUsesLesserWarning(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	setTestPrefixDB(t, map[string][]string{"XX": {"203.0.113.0/24"}})
	sid := loginAs(t, r, "op")

	form := url.Values{
		"target_ip": {"10.0.1.100"}, "country": {"XX"}, "reason": {"打这台"},
	}
	w := postFrom(t, r, sid, "203.0.113.9", "/scoped", form)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 %d,期望 400", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "10.0.1.100") {
		t.Errorf("定向版提示必须点出目标主机,好让人判断影响面:\n%s", body)
	}
	if !strings.Contains(body, `value="10.0.1.100"`) {
		t.Errorf("重渲染应回填目标主机:\n%s", body)
	}
}

func TestScopedBanCreate_UnrelatedScopeIsUnaffected(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})
	sid := loginAs(t, r, "op")

	form := url.Values{"country": {"XX"}, "reason": {"扫描"}}
	w := postFrom(t, r, sid, "203.0.113.9", "/scoped", form)
	if w.Code != http.StatusFound {
		t.Fatalf("状态码 %d,期望 302,body=%s", w.Code, w.Body.String())
	}
}

// GET /scoped/new 走的是"表单字段全为空串"的那条路。这条测试守着 scopedBanNew
// 里那四个空串:少了 country,模板里的 `eq .Code $.country` 就是 nil 和 string
// 相比,html/template 直接渲染报错 —— 页面白屏,而不是编译期发现。
func TestScopedBanNew_RendersWithPrefixDBPresent(t *testing.T) {
	db := newSelfBanDB(t)
	mkUser(t, db, "op", true)
	r := newWebRouter(t, db)
	setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})
	sid := loginAs(t, r, "op")

	w := getAs(t, r, sid, "/scoped/new")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d,期望 200,body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `<option value="XX"`) {
		t.Errorf("国家下拉应渲染出前缀库里的国家:\n%s", w.Body.String())
	}
}

func TestClientAddr_PrefersForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req

	addr, ok := clientAddr(c)
	if !ok {
		t.Fatal("应能解析出客户端地址")
	}
	// 装了反代时 RemoteIP 恒为环回,而 127.0.0.0/8 早已在硬保护集里 ——
	// 用 RemoteIP 这个检查就永远不会触发,等于白写。
	if addr.String() != "203.0.113.9" {
		t.Errorf("clientAddr = %s,期望 203.0.113.9(取 XFF 而不是 RemoteAddr)", addr)
	}
}

func TestParseAnyPrefix_AcceptsBareAddrAndCIDR(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":    "203.0.113.9/32",
		"203.0.113.0/24": "203.0.113.0/24",
		"203.0.113.7/24": "203.0.113.0/24", // 必须掩掉主机位,否则 Contains 判错
		"2001:db8::1":    "2001:db8::1/128",
	}
	for in, want := range cases {
		p, err := parseAnyPrefix(in)
		if err != nil {
			t.Errorf("parseAnyPrefix(%q): %v", in, err)
			continue
		}
		if p.String() != want {
			t.Errorf("parseAnyPrefix(%q) = %s,期望 %s", in, p, want)
		}
	}
	if _, err := parseAnyPrefix("garbage"); err == nil {
		t.Error("非法输入应报错")
	}
}
