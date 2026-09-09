package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// status/why 只能在挂着 XDP 的真机上跑起来,所以这里测的是它们唯一可测、
// 同时也最容易出错的部分:把 map 里的字节翻译成结论。翻错的代价是
// 排障时得出与事实相反的判断 —— 这正是这两个子命令要消灭的东西。

const testUptime = 10 * time.Hour

// liveValue / expiredValue 直接用写入侧的 KtimeDeadline 造值,而不是自己拼
// 一个数字:如果哪天 TTL 的基准从 uptime 改成别的,这些测试会跟着一起断,
// 而不是继续绿着骗人。
func liveValue(t *testing.T, ttlSecs int64, hits uint64, ruleID uint32) []byte {
	t.Helper()
	boot := time.Now().Add(-testUptime)
	return banmap.EncodeValue(banmap.Value{
		ExpiresAt: banmap.KtimeDeadline(boot, time.Now(), ttlSecs),
		Hits:      hits,
		RuleID:    ruleID,
	})
}

func expiredValue(t *testing.T, agoSecs int64, hits uint64) []byte {
	t.Helper()
	return banmap.EncodeValue(banmap.Value{
		ExpiresAt: uint64(testUptime) - uint64(agoSecs)*uint64(time.Second),
		Hits:      hits,
	})
}

func permanentValue(hits uint64, ruleID uint32) []byte {
	return banmap.EncodeValue(banmap.Value{ExpiresAt: 0, Hits: hits, RuleID: ruleID})
}

func newTestInspector() (*inspector, *fakeMap, *fakeMap, *fakeMap) {
	g := newFakeMap(banmap.MapGlobalBans)
	tg := newFakeMap(banmap.MapTargetHosts)
	s := newFakeMap(banmap.MapSrcBans)
	return &inspector{global: g, targets: tg, src: s, uptime: testUptime}, g, tg, s
}

func putGlobal(t *testing.T, m *fakeMap, prefix string, val []byte) {
	t.Helper()
	k, err := banmap.EncodeGlobalKey(netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatalf("EncodeGlobalKey(%s): %v", prefix, err)
	}
	if err := m.Put(k, val); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func putTarget(t *testing.T, m *fakeMap, addr string, tid uint32) {
	t.Helper()
	k, err := banmap.EncodeTargetKey(netip.MustParseAddr(addr))
	if err != nil {
		t.Fatalf("EncodeTargetKey(%s): %v", addr, err)
	}
	if err := m.Put(k, banmap.EncodeTargetID(tid)); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func putScoped(t *testing.T, m *fakeMap, tid uint32, prefix string, val []byte) {
	t.Helper()
	k, err := banmap.EncodeSrcKey(tid, netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatalf("EncodeSrcKey(%d, %s): %v", tid, prefix, err)
	}
	if err := m.Put(k, val); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func TestDescribeTTL_ThreeStates(t *testing.T) {
	permState, permDetail, permDrop := describeTTL(banmap.Value{ExpiresAt: 0}, testUptime)
	if permState != "LIVE" || !permDrop {
		t.Errorf("expires_at=0 是永久封禁,应为 LIVE 且正在丢包,实际 %q dropping=%v", permState, permDrop)
	}
	if !strings.Contains(permDetail, "永久") {
		t.Errorf("永久封禁的说明里应出现「永久」,实际 %q", permDetail)
	}

	live, _ := banmap.DecodeValue(liveValue(t, 600, 0, 0))
	state, detail, dropping := describeTTL(live, testUptime)
	if state != "LIVE" || !dropping {
		t.Errorf("未到期应为 LIVE 且正在丢包,实际 %q dropping=%v", state, dropping)
	}
	if !strings.Contains(detail, "剩余") {
		t.Errorf("未到期应报剩余时间,实际 %q", detail)
	}

	exp, _ := banmap.DecodeValue(expiredValue(t, 300, 0))
	state, detail, dropping = describeTTL(exp, testUptime)
	if state != "EXPIRED" {
		t.Errorf("已到期应为 EXPIRED,实际 %q", state)
	}
	if dropping {
		t.Error("已到期的记录不再丢包 —— 报成正在丢包会把排障引向完全相反的结论")
	}
	if !strings.Contains(detail, "放行") {
		t.Errorf("必须说明内核已放行(键未清理),实际 %q", detail)
	}
}

// 这是整套诊断里最关键的一条断言:XDP 从不删过期键,所以"map 里有这条记录"
// 与"这个 IP 正在被丢包"是两件事。输出必须把两者分开说。
func TestWriteStatus_SeparatesLiveFromExpired(t *testing.T) {
	in, g, _, _ := newTestInspector()
	putGlobal(t, g, "203.0.113.0/24", liveValue(t, 600, 12, 42))
	putGlobal(t, g, "198.51.100.5/32", expiredValue(t, 300, 7))

	var buf bytes.Buffer
	if err := in.writeStatus(&buf); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"203.0.113.0/24", "LIVE", "剩余",
		"198.51.100.5/32", "EXPIRED", "内核已放行",
		"rule_id=42", "已丢 12 包",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少 %q:\n%s", want, out)
		}
	}
}

func TestWriteStatus_MentionsIptablesInvisibility(t *testing.T) {
	in, _, _, _ := newTestInspector()
	var buf bytes.Buffer
	if err := in.writeStatus(&buf); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	out := buf.String()

	// 运维会带着"iptables 里什么都没有"的困惑跑到这里,第一屏就得回答这个问题。
	if !strings.Contains(out, "iptables") {
		t.Errorf("status 首行应说明规则不出现在 iptables 里:\n%s", out)
	}
	if !strings.Contains(out, banmap.PinDir) {
		t.Errorf("应打印 pin 目录,便于改用 bpftool:\n%s", out)
	}
}

func TestWriteStatus_EmptyMapsPointsElsewhere(t *testing.T) {
	in, _, _, _ := newTestInspector()
	var buf bytes.Buffer
	if err := in.writeStatus(&buf); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	if !strings.Contains(buf.String(), "原因不在 xdp-ban") {
		t.Errorf("map 全空时必须明确排除自己,否则运维会继续在这里绕:\n%s", buf.String())
	}
}

func TestWriteStatus_ResolvesScopedTargetName(t *testing.T) {
	in, _, tg, s := newTestInspector()
	putTarget(t, tg, "10.0.1.100", 1)
	putScoped(t, s, 1, "203.0.113.0/24", liveValue(t, 3600, 3, 9))
	// 一条 target_hosts 里已经没有对应主机的孤儿记录 —— 回滚时最容易漏掉的就是它。
	putScoped(t, s, 99, "198.51.100.0/24", liveValue(t, 3600, 1, 10))

	var buf bytes.Buffer
	if err := in.writeStatus(&buf); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "10.0.1.100") {
		t.Errorf("已知 target_id 应显示为主机地址:\n%s", out)
	}
	if !strings.Contains(out, "target_id=99") {
		t.Errorf("孤儿 target_id 必须原样报出来,不能悄悄吞掉:\n%s", out)
	}
}

func TestWriteCounters_ZeroDroppedExoneratesXDP(t *testing.T) {
	in, _, _, _ := newTestInspector()
	in.counters = make([]uint64, banmap.CntMax)
	in.counters[banmap.CntPassed] = 100

	var buf bytes.Buffer
	in.writeCounters(&buf)
	out := buf.String()

	if !strings.Contains(out, "dropped 为 0") {
		t.Errorf("dropped=0 时应直接排除 xdp-ban:\n%s", out)
	}
	if !strings.Contains(out, banmap.CounterLabel(banmap.CntNotTarget)) {
		t.Errorf("四个计数器都应打印:\n%s", out)
	}
}

func TestWriteCounters_UnreadableSaysWhy(t *testing.T) {
	in, _, _, _ := newTestInspector()
	in.counters = nil

	var buf bytes.Buffer
	in.writeCounters(&buf)
	if !strings.Contains(buf.String(), "读不到") {
		t.Errorf("读不到计数器时要说明原因,而不是打一串 0:\n%s", buf.String())
	}
}

// why 的核心价值:拿 /32 去问,答出覆盖它的那条网段规则 —— 与内核 LPM 的判定一致。
func TestWriteWhy_LPMHitsCoveringPrefix(t *testing.T) {
	in, g, _, _ := newTestInspector()
	putGlobal(t, g, "203.0.113.0/24", liveValue(t, 600, 5, 42))

	var buf bytes.Buffer
	dropping, err := in.writeWhy(&buf, netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatalf("writeWhy: %v", err)
	}
	if !dropping {
		t.Fatal("203.0.113.7 被 /24 规则覆盖,应判定为正在被丢弃")
	}
	out := buf.String()
	if !strings.Contains(out, "命中") || !strings.Contains(out, "rule_id=42") {
		t.Errorf("应报出命中的规则 id:\n%s", out)
	}
	if !strings.Contains(out, "正在被 XDP 丢弃") {
		t.Errorf("结论行缺失:\n%s", out)
	}
	if !strings.Contains(out, "bpftool") {
		t.Errorf("Web 界面可能正因这条规则而进不去,必须给出 bpftool 兜底路径:\n%s", out)
	}
}

func TestWriteWhy_ExpiredEntryIsNotDropping(t *testing.T) {
	in, g, _, _ := newTestInspector()
	putGlobal(t, g, "203.0.113.0/24", expiredValue(t, 60, 5))

	var buf bytes.Buffer
	dropping, err := in.writeWhy(&buf, netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatalf("writeWhy: %v", err)
	}
	if dropping {
		t.Fatal("过期规则只是键没被清理,内核已放行 —— 判定为正在丢包是方向性错误")
	}
	out := buf.String()
	if !strings.Contains(out, "命中") {
		t.Errorf("键确实还在,应如实报命中:\n%s", out)
	}
	if !strings.Contains(out, "没有被 XDP 丢弃") {
		t.Errorf("结论必须是未被丢弃:\n%s", out)
	}
}

func TestWriteWhy_PermanentBanIsDropping(t *testing.T) {
	in, g, _, _ := newTestInspector()
	putGlobal(t, g, "203.0.113.7/32", permanentValue(1, 3))

	var buf bytes.Buffer
	dropping, err := in.writeWhy(&buf, netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatalf("writeWhy: %v", err)
	}
	if !dropping {
		t.Error("expires_at=0 是永久封禁,内核永不放行")
	}
}

func TestWriteWhy_ScopedHitNamesTarget(t *testing.T) {
	in, _, tg, s := newTestInspector()
	putTarget(t, tg, "10.0.1.100", 1)
	putTarget(t, tg, "10.0.1.200", 2)
	putScoped(t, s, 2, "203.0.113.0/24", liveValue(t, 3600, 8, 0))

	var buf bytes.Buffer
	dropping, err := in.writeWhy(&buf, netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatalf("writeWhy: %v", err)
	}
	if !dropping {
		t.Fatal("定向规则命中也算正在被丢弃(只是仅对该目标)")
	}
	out := buf.String()
	if !strings.Contains(out, "10.0.1.200") || !strings.Contains(out, "target_id=2") {
		t.Errorf("应指明是哪台目标主机:\n%s", out)
	}
	if strings.Contains(out, "→ 10.0.1.100") {
		t.Errorf("没有规则的目标不应出现在命中列表里:\n%s", out)
	}
}

func TestWriteWhy_CleanAddressPointsElsewhere(t *testing.T) {
	in, g, tg, _ := newTestInspector()
	putGlobal(t, g, "198.51.100.0/24", liveValue(t, 600, 1, 1))
	putTarget(t, tg, "10.0.1.100", 1)

	var buf bytes.Buffer
	dropping, err := in.writeWhy(&buf, netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatalf("writeWhy: %v", err)
	}
	if dropping {
		t.Fatal("未命中任何规则,不应判定为被丢弃")
	}
	out := buf.String()
	if !strings.Contains(out, "未命中") {
		t.Errorf("应明说未命中:\n%s", out)
	}
	// 这里最容易犯的错是让人以为"xdp-ban 说没封,那就是没被封" —— 得把边界划清。
	if !strings.Contains(out, "conntrack") {
		t.Errorf("必须声明只看了 XDP 层,其余仍需排查:\n%s", out)
	}
}

func TestLookupPrefix_IPv6IsAlwaysMiss(t *testing.T) {
	in, g, _, _ := newTestInspector()
	putGlobal(t, g, "0.0.0.0/0", permanentValue(0, 0))

	// XDP 侧只处理 ETH_P_IP,IPv6 的包连 map 都不会查 —— 即使有一条 0.0.0.0/0。
	hit, _, err := lookupPrefix(in.global, netip.MustParseAddr("2001:db8::1"), 0)
	if err != nil {
		t.Fatalf("lookupPrefix: %v", err)
	}
	if hit {
		t.Error("IPv6 地址不该在 IPv4 ban map 里命中")
	}
}

func TestLookupPrefix_PrefersLongestMatch(t *testing.T) {
	in, g, _, _ := newTestInspector()
	putGlobal(t, g, "203.0.113.0/24", liveValue(t, 600, 0, 1))
	putGlobal(t, g, "203.0.113.7/32", liveValue(t, 600, 0, 2))

	hit, v, err := lookupPrefix(in.global, netip.MustParseAddr("203.0.113.7"), 0)
	if err != nil {
		t.Fatalf("lookupPrefix: %v", err)
	}
	if !hit {
		t.Fatal("应命中")
	}
	if v.RuleID != 2 {
		t.Errorf("命中 rule_id=%d,期望 2(/32 比 /24 更长)—— 回滚会撤错规则", v.RuleID)
	}
}
