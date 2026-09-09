package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

type fakeMap struct {
	name    string
	entries map[string][]byte
	putErr  error
	puts    int
}

func newFakeMap(name string) *fakeMap {
	return &fakeMap{name: name, entries: make(map[string][]byte)}
}

func (m *fakeMap) Put(key, value any) error {
	if m.putErr != nil {
		return m.putErr
	}
	kb, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%s: key 类型应为 []byte,实际 %T", m.name, key)
	}
	vb, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("%s: value 类型应为 []byte,实际 %T", m.name, value)
	}
	m.entries[string(kb)] = vb
	m.puts++
	return nil
}

func (m *fakeMap) Delete(key any) error {
	kb, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%s: key 类型应为 []byte", m.name)
	}
	delete(m.entries, string(kb))
	return nil
}

func (m *fakeMap) Iterate() MapIterator {
	keys := make([][]byte, 0, len(m.entries))
	vals := make([][]byte, 0, len(m.entries))
	for k, v := range m.entries {
		keys = append(keys, []byte(k))
		vals = append(vals, v)
	}
	return &fakeMapIterator{keys: keys, vals: vals}
}

// Lookup 模拟 LPM_TRIE 的最长前缀匹配,不是简单的 map 取值。
//
// 必须这样做:`xdp-ban why 203.0.113.7` 的全部价值就在于"拿 /32 去问,答出
// 覆盖它的那条 /24 规则" —— 这正是 xdp_filter.c 里内核替我们做的事。如果测试
// 里只做精确匹配,最容易错的那条路径(网段规则封住了单个 IP)就永远测不到。
//
// 键的布局由长度唯一决定,与 banmap 的编码一一对应:
//   - 8 字节 = 全局键,prefixlen[0:4] + addr[4:8]
//   - 12 字节 = 定向键,prefixlen[0:4](含 32 位 target_id)+ target_id[4:8] + addr[8:12]
func (m *fakeMap) Lookup(key, valueOut any) error {
	kb, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%s: key 类型应为 []byte,实际 %T", m.name, key)
	}
	out, ok := valueOut.(*[]byte)
	if !ok {
		return fmt.Errorf("%s: valueOut 类型应为 *[]byte,实际 %T", m.name, valueOut)
	}

	qBits, qTID, qAddr, err := splitFakeKey(kb)
	if err != nil {
		return err
	}

	bestBits := -1
	var best []byte
	for k, v := range m.entries {
		eb := []byte(k)
		if len(eb) != len(kb) {
			continue
		}
		bits, tid, addr, err := splitFakeKey(eb)
		if err != nil {
			continue
		}
		if tid != qTID || bits > qBits {
			continue
		}
		if !netip.PrefixFrom(addr, bits).Contains(qAddr) {
			continue
		}
		if bits > bestBits {
			bestBits, best = bits, v
		}
	}
	if bestBits < 0 {
		return ebpf.ErrKeyNotExist
	}
	*out = best
	return nil
}

// splitFakeKey 把 fake map 的键拆成(源前缀长度, target_id, 源地址)。
// 全局键没有 target_id,统一返回 0,这样匹配逻辑不必分叉。
func splitFakeKey(b []byte) (int, uint32, netip.Addr, error) {
	var a4 [4]byte
	switch len(b) {
	case banmap.GlobalKeySize:
		prefix, err := banmap.DecodeGlobalKey(b)
		if err != nil {
			return 0, 0, netip.Addr{}, err
		}
		return prefix.Bits(), 0, prefix.Addr(), nil
	case banmap.SrcKeySize:
		tid, prefix, err := banmap.DecodeSrcKey(b)
		if err != nil {
			return 0, 0, netip.Addr{}, err
		}
		return prefix.Bits(), tid, prefix.Addr(), nil
	default:
		copy(a4[:], b)
		return 0, 0, netip.AddrFrom4(a4), fmt.Errorf("无法识别的 key 长度 %d", len(b))
	}
}

type fakeMapIterator struct {
	keys [][]byte
	vals [][]byte
	pos  int
}

func (it *fakeMapIterator) Next(keyOut, valueOut any) bool {
	if it.pos >= len(it.keys) {
		return false
	}
	*(keyOut.(*[]byte)) = it.keys[it.pos]
	*(valueOut.(*[]byte)) = it.vals[it.pos]
	it.pos++
	return true
}

func newTestMaps() (*banMaps, *fakeMap, *fakeMap, *fakeMap) {
	g := newFakeMap(banmap.MapGlobalBans)
	t := newFakeMap(banmap.MapTargetHosts)
	s := newFakeMap(banmap.MapSrcBans)

	boot := time.Now().Add(-time.Hour)
	return newBanMaps(g, t, s, boot), g, t, s
}

func TestApply_SingleHostGoesToGlobalMap(t *testing.T) {
	bm, global, targets, src := newTestMaps()

	err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600, ReqID: 42})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if global.puts != 1 {
		t.Errorf("全局表写入 %d 次,期望 1", global.puts)
	}
	if targets.puts != 0 || src.puts != 0 {
		t.Errorf("单点封禁不应碰定向表(targets=%d src=%d)", targets.puts, src.puts)
	}

	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.7/32"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Errorf("未找到期望的 key %v;实际键集合 %v", wantKey, keysOf(global))
	}
}

func TestApply_GlobalBanSupportsCIDR(t *testing.T) {
	bm, global, _, _ := newTestMaps()

	if err := bm.Apply(&BanPayload{Target: "203.0.113.0/24", TTLSecs: 0}); err != nil {
		t.Fatalf("Apply CIDR: %v", err)
	}

	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.0/24"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Errorf("网段封禁未写入正确的 key")
	}

	if got := binary.LittleEndian.Uint32(wantKey[0:4]); got != 24 {
		t.Errorf("prefixlen = %d,期望 24", got)
	}
}

func TestApply_ScopedWritesBothMaps(t *testing.T) {
	bm, global, targets, src := newTestMaps()

	err := bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     []string{"203.0.113.0/24", "198.51.100.0/24", "1.2.3.4"},
		TTLSecs:      3600,
		ReqID:        7,
	})
	if err != nil {
		t.Fatalf("Apply scoped: %v", err)
	}

	if targets.puts != 1 {
		t.Errorf("target_hosts 写入 %d 次,期望 1", targets.puts)
	}
	if src.puts != 3 {
		t.Errorf("src_ban 写入 %d 次,期望 3(每条源前缀一次)", src.puts)
	}
	if global.puts != 0 {
		t.Errorf("范围封禁不应写全局表")
	}

	for k := range src.entries {
		kb := []byte(k)
		if len(kb) != banmap.SrcKeySize {
			t.Fatalf("src key 长度 %d,期望 %d", len(kb), banmap.SrcKeySize)
		}
		pl := binary.LittleEndian.Uint32(kb[0:4])
		if pl < 32 {
			t.Errorf("prefixlen = %d < 32,target_id 不再是精确匹配", pl)
		}
		tid := binary.LittleEndian.Uint32(kb[4:8])
		if tid == 0 {
			t.Errorf("target_id 为 0 —— 0 应保留不用,以区分'未分配'")
		}
	}
}

func TestRevokeGlobal_DeletesPreviouslyAppliedKey(t *testing.T) {
	bm, global, _, _ := newTestMaps()

	if err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.7/32"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Fatalf("Apply 后未找到 key,前提条件不满足")
	}

	if err := bm.RevokeGlobal("203.0.113.7"); err != nil {
		t.Fatalf("RevokeGlobal: %v", err)
	}
	if _, ok := global.entries[string(wantKey)]; ok {
		t.Errorf("RevokeGlobal 后 key 仍存在")
	}
}

func TestRevokeGlobal_NeverAppliedIsNotError(t *testing.T) {
	bm, _, _, _ := newTestMaps()

	if err := bm.RevokeGlobal("198.51.100.9"); err != nil {
		t.Errorf("撤销一个从未下发过的全局封禁应静默成功,实际报错: %v", err)
	}
}

func TestRevokeScoped_DeletesPreviouslyAppliedKeys(t *testing.T) {
	bm, _, _, src := newTestMaps()

	prefixes := []string{"203.0.113.0/24", "198.51.100.0/24"}
	if err := bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     prefixes,
		TTLSecs:      3600,
	}); err != nil {
		t.Fatalf("Apply scoped: %v", err)
	}
	if src.puts != 2 {
		t.Fatalf("Apply 后 src puts = %d,期望 2", src.puts)
	}

	if err := bm.RevokeScoped("10.0.1.100", prefixes); err != nil {
		t.Fatalf("RevokeScoped: %v", err)
	}
	if len(src.entries) != 0 {
		t.Errorf("RevokeScoped 后 src_ban 仍残留 %d 条", len(src.entries))
	}
}

func TestRevokeScoped_UnknownTargetIsNotError(t *testing.T) {
	bm, _, _, _ := newTestMaps()

	err := bm.RevokeScoped("10.0.1.200", []string{"203.0.113.0/24"})
	if err != nil {
		t.Errorf("撤销一个从未 ensureTarget 过的目标应静默成功(target_id 映射非持久化),实际报错: %v", err)
	}
}

func TestEnsureTarget_ReusesID(t *testing.T) {
	bm, _, targets, _ := newTestMaps()

	addr := netip.MustParseAddr("10.0.1.100")
	id1, err := bm.ensureTarget(addr)
	if err != nil {
		t.Fatalf("ensureTarget: %v", err)
	}
	id2, err := bm.ensureTarget(addr)
	if err != nil {
		t.Fatalf("ensureTarget 二次: %v", err)
	}

	if id1 != id2 {
		t.Errorf("同一目标分配了不同 id: %d vs %d", id1, id2)
	}
	if targets.puts != 1 {
		t.Errorf("target_hosts 被重复写入 %d 次", targets.puts)
	}

	id3, _ := bm.ensureTarget(netip.MustParseAddr("10.0.1.200"))
	if id3 == id1 {
		t.Errorf("不同目标复用了同一 id %d", id1)
	}
}

func TestApply_MapFullReturnsError(t *testing.T) {
	bm, global, _, src := newTestMaps()
	global.putErr = fmt.Errorf("argument list too long")

	err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600})
	if err == nil {
		t.Fatal("map 满时必须返回错误")
	}

	src.putErr = fmt.Errorf("argument list too long")
	err = bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     []string{"1.0.0.0/8", "2.0.0.0/8"},
	})
	if err == nil {
		t.Fatal("src_ban 满时必须返回错误")
	}
	if !contains(err.Error(), "已写入") {
		t.Errorf("错误信息应说明已写入条数,便于判断部分生效范围,实际: %v", err)
	}
}

func TestKtimeDeadline_UsesUptimeNotUnix(t *testing.T) {
	boot := time.Now().Add(-2 * time.Hour)
	now := time.Now()

	got := banmap.KtimeDeadline(boot, now, 600)

	wantLow := uint64((2*time.Hour + 590*time.Second).Nanoseconds())
	wantHigh := uint64((2*time.Hour + 610*time.Second).Nanoseconds())
	if got < wantLow || got > wantHigh {
		t.Errorf("deadline = %d ns,期望约 %d..%d(uptime + TTL)", got, wantLow, wantHigh)
	}

	if got > uint64(1e17) {
		t.Errorf("deadline = %d 看起来是 Unix 时间而非 ktime,所有 TTL 判断都会错", got)
	}
}

func TestKtimeDeadline_ZeroTTLMeansPermanent(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	for _, ttl := range []int64{0, -1, -3600} {
		if got := banmap.KtimeDeadline(boot, time.Now(), ttl); got != 0 {
			t.Errorf("TTL=%d 应表示永久(deadline=0),实际 %d", ttl, got)
		}
	}
}

func TestApply_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		payload BanPayload
	}{
		{"空目标", BanPayload{Target: ""}},
		{"非法目标", BanPayload{Target: "not-an-ip"}},
		{"IPv6 目标", BanPayload{Target: "2001:db8::1"}},
		{"范围封禁目标非法", BanPayload{ScopedTarget: "bad", Prefixes: []string{"1.0.0.0/8"}}},
		{"范围封禁目标为网段", BanPayload{ScopedTarget: "10.0.0.0/8", Prefixes: []string{"1.0.0.0/8"}}},
		{"范围封禁前缀非法", BanPayload{ScopedTarget: "10.0.1.1", Prefixes: []string{"garbage"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bm, _, _, _ := newTestMaps()
			if err := bm.Apply(&tc.payload); err == nil {
				t.Errorf("应拒绝: %+v", tc.payload)
			}
		})
	}
}

func TestValueLayout_MatchesKernelStruct(t *testing.T) {
	v := banmap.Value{ExpiresAt: 0x1122334455667788, Hits: 42, RuleID: 7}
	b := banmap.EncodeValue(v)

	if len(b) != banmap.ValueSize {
		t.Fatalf("value 长度 %d,期望 %d(u64+u64+u32+pad)", len(b), banmap.ValueSize)
	}
	back, err := banmap.DecodeValue(b)
	if err != nil {
		t.Fatalf("DecodeValue: %v", err)
	}
	if back != v {
		t.Errorf("编解码不一致: %+v → %+v", v, back)
	}
}

// restoreTargets 是 pin map 带来的唯一新风险的解药。map 跨进程重启存活,内存里
// 的 addr→target_id 映射不会;不读回来,nextTargetID 会从 1 重新发号,把已经
// 被别人占用的 target_id 交给另一台主机,src_ban 里那批旧源前缀会立刻作用在
// 新目标上。这一组测试盯的就是这件事。
func TestRestoreTargets_RebuildsMappingAndBumpsNextID(t *testing.T) {
	_, _, targets, _ := newTestMaps()

	for addr, tid := range map[string]uint32{"10.0.1.100": 1, "10.0.1.200": 7} {
		k, err := banmap.EncodeTargetKey(netip.MustParseAddr(addr))
		if err != nil {
			t.Fatalf("EncodeTargetKey(%s): %v", addr, err)
		}
		if err := targets.Put(k, banmap.EncodeTargetID(tid)); err != nil {
			t.Fatalf("预置 target_hosts: %v", err)
		}
	}

	// 新进程:map 里有内容,内存映射是空的。
	bm2 := newBanMaps(newFakeMap(banmap.MapGlobalBans), targets,
		newFakeMap(banmap.MapSrcBans), time.Now().Add(-time.Hour))

	n, err := bm2.restoreTargets()
	if err != nil {
		t.Fatalf("restoreTargets: %v", err)
	}
	if n != 2 {
		t.Errorf("恢复了 %d 条,期望 2", n)
	}
	if got := bm2.targetIDs["10.0.1.200"]; got != 7 {
		t.Errorf("10.0.1.200 的 target_id = %d,期望 7", got)
	}

	// 关键断言:新目标必须拿到 8,而不是撞上已被占用的 1..7。
	id, err := bm2.ensureTarget(netip.MustParseAddr("10.0.2.1"))
	if err != nil {
		t.Fatalf("ensureTarget: %v", err)
	}
	if id != 8 {
		t.Errorf("新目标分配到 target_id=%d —— 期望 8;复用旧 id 会让旧 src_ban 规则突然作用在新目标上", id)
	}
}

func TestRestoreTargets_RejectsReservedZeroID(t *testing.T) {
	_, _, targets, _ := newTestMaps()
	k, _ := banmap.EncodeTargetKey(netip.MustParseAddr("10.0.1.100"))
	if err := targets.Put(k, banmap.EncodeTargetID(0)); err != nil {
		t.Fatalf("预置: %v", err)
	}

	bm2 := newBanMaps(newFakeMap(banmap.MapGlobalBans), targets,
		newFakeMap(banmap.MapSrcBans), time.Now())
	if _, err := bm2.restoreTargets(); err == nil {
		t.Error("target_id=0 是保留值,map 内容不可信时必须报错而不是半恢复")
	}
	if len(bm2.targetIDs) != 0 {
		t.Errorf("失败时不应留下半张映射表,实际 %d 条", len(bm2.targetIDs))
	}
}

func TestRestoreTargets_EmptyMapIsNotError(t *testing.T) {
	bm, _, _, _ := newTestMaps()
	n, err := bm.restoreTargets()
	if err != nil {
		t.Fatalf("空 map 应静默成功: %v", err)
	}
	if n != 0 {
		t.Errorf("恢复了 %d 条,期望 0", n)
	}
	if bm.nextTargetID != 1 {
		t.Errorf("nextTargetID = %d,期望保持 1", bm.nextTargetID)
	}
}

func keysOf(m *fakeMap) [][]byte {
	out := make([][]byte, 0, len(m.entries))
	for k := range m.entries {
		out = append(out, []byte(k))
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
