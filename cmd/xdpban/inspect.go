package main

// 这个文件是 xdp-ban 唯一的控制台排障出口。
//
// 为什么非要有它:XDP 挂在 netfilter 之前,规则永远不会出现在 `iptables -L`、
// `nft list ruleset`、`firewall-cmd --list-all` 里。运维手上只有"连接被切了"
// 这一个现象,却没有任何一条常用命令会指向 xdp-ban。最坏的情况是把自己的来源
// 地址封了 —— 那台机器的 Web 界面(唯一能解释原因的地方)也一起没了,只剩控制台。
//
// 所以 status/why 有三条硬要求:
//  1. 不 attach 任何程序、不写任何 map,随时可以跑,跑几次都一样;
//  2. 不碰 SQLite —— DB 记的是"我们打算封什么",内核 map 才是"此刻在丢什么"。
//     排障要的是后者,而且 DB 文件此刻正被守护进程拿着;
//  3. 找不到 pin 时给出确切的下一步,而不是一句 no such file。

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// mapReader 是 status/why 用到的全部只读能力。抽成接口是为了能用
// executor_test.go 里那套 fakeMap 直接测输出:这些代码只在真机上跑得起来,
// 而"剩余时间、过期判定、命中与否"恰好是最容易写错、又最不该错的部分。
type mapReader interface {
	Lookup(key, valueOut any) error
	Iterate() MapIterator
}

// inspector 持有一次诊断快照所需的一切。counters 传的是已按 CPU 求和的结果
// (nil = 读不到),attachments 传的是"网卡 → prog id"文本(nil = 查不到),
// 这样格式化逻辑不必知道 percpu map 和 netlink 长什么样。
type inspector struct {
	global      mapReader
	targets     mapReader
	src         mapReader
	counters    []uint64
	uptime      time.Duration
	attachments []string
}

// globalEntry / scopedEntry / targetEntry 是解码后的一条 map 记录。
type globalEntry struct {
	Prefix netip.Prefix
	Value  banmap.Value
}

type scopedEntry struct {
	TargetID uint32
	Target   string // 解析不出来时是 "target_id=N"
	Prefix   netip.Prefix
	Value    banmap.Value
}

type targetEntry struct {
	Addr netip.Addr
	ID   uint32
}

func (in *inspector) globalEntries() ([]globalEntry, error) {
	var out []globalEntry
	it := in.global.Iterate()
	var key, val []byte
	for it.Next(&key, &val) {
		prefix, err := banmap.DecodeGlobalKey(key)
		if err != nil {
			return nil, fmt.Errorf("解码 %s key: %w", banmap.MapGlobalBans, err)
		}
		v, err := banmap.DecodeValue(val)
		if err != nil {
			return nil, fmt.Errorf("解码 %s value (%s): %w", banmap.MapGlobalBans, prefix, err)
		}
		out = append(out, globalEntry{Prefix: prefix, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix.String() < out[j].Prefix.String() })
	return out, nil
}

func (in *inspector) targetEntries() ([]targetEntry, error) {
	var out []targetEntry
	it := in.targets.Iterate()
	var key, val []byte
	for it.Next(&key, &val) {
		addr, err := banmap.DecodeTargetKey(key)
		if err != nil {
			return nil, fmt.Errorf("解码 %s key: %w", banmap.MapTargetHosts, err)
		}
		id, err := banmap.DecodeTargetID(val)
		if err != nil {
			return nil, fmt.Errorf("解码 %s value (%s): %w", banmap.MapTargetHosts, addr, err)
		}
		out = append(out, targetEntry{Addr: addr, ID: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (in *inspector) scopedEntries(names map[uint32]string) ([]scopedEntry, error) {
	var out []scopedEntry
	it := in.src.Iterate()
	var key, val []byte
	for it.Next(&key, &val) {
		tid, prefix, err := banmap.DecodeSrcKey(key)
		if err != nil {
			return nil, fmt.Errorf("解码 %s key: %w", banmap.MapSrcBans, err)
		}
		v, err := banmap.DecodeValue(val)
		if err != nil {
			return nil, fmt.Errorf("解码 %s value: %w", banmap.MapSrcBans, err)
		}
		name, ok := names[tid]
		if !ok {
			name = fmt.Sprintf("target_id=%d(target_hosts 里已无此项)", tid)
		}
		out = append(out, scopedEntry{TargetID: tid, Target: name, Prefix: prefix, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetID != out[j].TargetID {
			return out[i].TargetID < out[j].TargetID
		}
		return out[i].Prefix.String() < out[j].Prefix.String()
	})
	return out, nil
}

// describeTTL 把一条记录的到期状态说成一句人话。
//
// 这里必须把"键还在 map 里"和"此刻正在丢包"分开:XDP 侧查到过期记录只是放行,
// 从不删键(内核里没有定时器,也没有控制面清扫器)。看到一条记录就断定 IP 被封,
// 是这套设计最容易得出的错误结论。
func describeTTL(v banmap.Value, uptime time.Duration) (state string, detail string, dropping bool) {
	st, d := banmap.ClassifyTTL(v.ExpiresAt, uptime)
	switch st {
	case banmap.TTLPermanent:
		return "LIVE", "永久(无 TTL)", true
	case banmap.TTLLive:
		return "LIVE", "剩余 " + d.Round(time.Second).String(), true
	default:
		return "EXPIRED", "已过期 " + d.Round(time.Second).String() + ",内核已放行(键未清理)", false
	}
}

func (in *inspector) writeStatus(w io.Writer) error {
	fmt.Fprintf(w, "xdp-ban %s —— XDP 规则不出现在 iptables/nft/firewalld 里,下面是内核侧的权威事实\n\n", Version)
	fmt.Fprintf(w, "pin 目录      %s\n", banmap.PinDir)
	if len(in.attachments) == 0 {
		fmt.Fprintf(w, "XDP 挂载      (查不到;需 root,或此刻确实没有网卡挂着 XDP 程序)\n")
	} else {
		for i, a := range in.attachments {
			label := "XDP 挂载      "
			if i > 0 {
				label = "              "
			}
			fmt.Fprintf(w, "%s%s\n", label, a)
		}
	}
	fmt.Fprintf(w, "系统 uptime   %s(TTL 的换算基准)\n", in.uptime.Round(time.Second))

	globals, err := in.globalEntries()
	if err != nil {
		return err
	}
	targets, err := in.targetEntries()
	if err != nil {
		return err
	}
	names := make(map[uint32]string, len(targets))
	for _, t := range targets {
		names[t.ID] = t.Addr.String()
	}
	scoped, err := in.scopedEntries(names)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "\n全局封禁 %s(按源地址,对所有目标生效): %d 条\n",
		banmap.MapGlobalBans, len(globals))
	for _, e := range globals {
		state, detail, _ := describeTTL(e.Value, in.uptime)
		fmt.Fprintf(w, "  %-21s %-7s %-34s 已丢 %d 包  rule_id=%d\n",
			e.Prefix, state, detail, e.Value.Hits, e.Value.RuleID)
	}

	fmt.Fprintf(w, "\n保护目标 %s: %d 台\n", banmap.MapTargetHosts, len(targets))
	for _, t := range targets {
		fmt.Fprintf(w, "  %-21s target_id=%d\n", t.Addr, t.ID)
	}

	fmt.Fprintf(w, "\n定向封禁 %s(源 → 目标): %d 条\n", banmap.MapSrcBans, len(scoped))
	for _, e := range scoped {
		state, detail, _ := describeTTL(e.Value, in.uptime)
		fmt.Fprintf(w, "  %-21s → %-16s %-7s %-34s 已丢 %d 包\n",
			e.Prefix, e.Target, state, detail, e.Value.Hits)
	}

	in.writeCounters(w)

	if len(globals) == 0 && len(scoped) == 0 {
		fmt.Fprintf(w, "\nmap 里没有任何封禁规则。如果连接确实被切了,原因不在 xdp-ban ——\n"+
			"接着查 iptables/nft、路由、conntrack、上游设备。\n")
	}
	return nil
}

func (in *inspector) writeCounters(w io.Writer) {
	fmt.Fprintf(w, "\n内核计数器 %s(自程序加载起累计,已按 CPU 求和)\n", banmap.MapCounters)
	if in.counters == nil {
		fmt.Fprintf(w, "  (读不到 —— 需 root,或运行的是未 pin counters 的旧版本)\n")
		return
	}
	for i, n := range in.counters {
		fmt.Fprintf(w, "  %-34s %d\n", banmap.CounterLabel(i), n)
	}
	if len(in.counters) > banmap.CntDropped && in.counters[banmap.CntDropped] == 0 {
		fmt.Fprintf(w, "  ↑ dropped 为 0:XDP 从未丢过任何包,断连不是这里造成的。\n")
	}
}

// writeWhy 回答"这个 IP 此刻在被 XDP 丢包吗,为什么"。
// 返回 true 表示确实正在被丢 —— 调用方据此给出非零退出码,方便脚本判断。
func (in *inspector) writeWhy(w io.Writer, addr netip.Addr) (bool, error) {
	fmt.Fprintf(w, "查询 %s(uptime 基准 %s)\n\n", addr, in.uptime.Round(time.Second))

	dropping := false

	// 全局表是 LPM_TRIE:拿 /32 去查,内核自动做最长前缀匹配,命中的可能是
	// 某条更短的网段规则。这正是 XDP 侧的判定方式,所以查询结果与实际行为一致。
	hit, gv, err := lookupPrefix(in.global, addr, 0)
	if err != nil {
		return false, err
	}
	if !hit {
		fmt.Fprintf(w, "全局封禁 %s: 未命中\n", banmap.MapGlobalBans)
	} else {
		state, detail, live := describeTTL(gv, in.uptime)
		dropping = dropping || live
		fmt.Fprintf(w, "全局封禁 %s: 命中\n", banmap.MapGlobalBans)
		fmt.Fprintf(w, "  %s,%s,该规则累计丢弃 %d 包,rule_id=%d\n",
			state, detail, gv.Hits, gv.RuleID)
		if live {
			fmt.Fprintf(w, "  → 撤销:Web 界面「IP 查询」里对 rule_id=%d 回滚;\n"+
				"     Web 界面也进不去时,`bpftool map delete pinned %s/%s key ...`\n",
				gv.RuleID, banmap.PinDir, banmap.MapGlobalBans)
		}
	}

	targets, err := in.targetEntries()
	if err != nil {
		return false, err
	}
	var scopedHits []string
	for _, t := range targets {
		ok, v, err := lookupPrefix(in.src, addr, t.ID)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		state, detail, live := describeTTL(v, in.uptime)
		dropping = dropping || live
		scopedHits = append(scopedHits, fmt.Sprintf("  → %s(target_id=%d): %s,%s,已丢 %d 包",
			t.Addr, t.ID, state, detail, v.Hits))
	}
	if len(scopedHits) == 0 {
		fmt.Fprintf(w, "定向封禁 %s: 未命中(已查 %d 台保护目标)\n", banmap.MapSrcBans, len(targets))
	} else {
		fmt.Fprintf(w, "定向封禁 %s: 命中 %d 条\n", banmap.MapSrcBans, len(scopedHits))
		for _, line := range scopedHits {
			fmt.Fprintln(w, line)
		}
	}

	fmt.Fprintln(w)
	if dropping {
		fmt.Fprintf(w, "结论: %s 此刻正在被 XDP 丢弃。\n", addr)
	} else {
		fmt.Fprintf(w, "结论: %s 没有被 XDP 丢弃。\n", addr)
		fmt.Fprintf(w, "      这里只看了 XDP 层;iptables/nft、路由、conntrack、"+
			"上游设备仍需另外排查。\n")
	}
	return dropping, nil
}

// lookupPrefix 用 /32 精确地址去查 LPM_TRIE。targetID 为 0 时查全局表
// (key 只有 prefixlen+src_ip),非 0 时查定向表(key 多一段 target_id)。
func lookupPrefix(m mapReader, addr netip.Addr, targetID uint32) (bool, banmap.Value, error) {
	if !addr.Is4() {
		// XDP 侧只处理 ETH_P_IP,IPv6 的包连 map 都不会查。
		return false, banmap.Value{}, nil
	}
	host := netip.PrefixFrom(addr, 32)

	var key []byte
	var err error
	if targetID == 0 {
		key, err = banmap.EncodeGlobalKey(host)
	} else {
		key, err = banmap.EncodeSrcKey(targetID, host)
	}
	if err != nil {
		return false, banmap.Value{}, err
	}

	var raw []byte
	if err := m.Lookup(key, &raw); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, banmap.Value{}, nil
		}
		return false, banmap.Value{}, fmt.Errorf("查 map: %w", err)
	}
	v, err := banmap.DecodeValue(raw)
	if err != nil {
		return false, banmap.Value{}, err
	}
	return true, v, nil
}

// pinnedMaps 是从 bpffs 只读打开的四张 map。
type pinnedMaps struct {
	global   *ebpf.Map
	targets  *ebpf.Map
	src      *ebpf.Map
	counters *ebpf.Map
}

func (p *pinnedMaps) Close() {
	for _, m := range []*ebpf.Map{p.global, p.targets, p.src, p.counters} {
		if m != nil {
			m.Close()
		}
	}
}

// openPinnedMaps 只读打开 pin 住的 map。counters 打不开不算失败 —— 它是加分项,
// 少了它照样能回答"这个 IP 在不在被封"。
func openPinnedMaps() (*pinnedMaps, error) {
	if _, err := os.Stat(banmap.PinDir); err != nil {
		return nil, fmt.Errorf("找不到 pin 目录 %s。可能的原因,按概率排:\n"+
			"  1. xdp-ban 没在运行 —— systemctl status xdp-ban\n"+
			"  2. bpffs 没挂载 —— mount | grep /sys/fs/bpf,没有就 mount -t bpf bpf /sys/fs/bpf 后重启 xdp-ban\n"+
			"  3. 运行的是不 pin map 的旧版本 —— 升级后重启\n"+
			"原始错误: %w", banmap.PinDir, err)
	}

	opts := &ebpf.LoadPinOptions{ReadOnly: true}
	open := func(name string) (*ebpf.Map, error) {
		m, err := ebpf.LoadPinnedMap(filepath.Join(banmap.PinDir, name), opts)
		if err != nil {
			return nil, fmt.Errorf("打开 %s/%s: %w(读 pin 需要 root)", banmap.PinDir, name, err)
		}
		return m, nil
	}

	p := &pinnedMaps{}
	var err error
	if p.global, err = open(banmap.MapGlobalBans); err != nil {
		p.Close()
		return nil, err
	}
	if p.targets, err = open(banmap.MapTargetHosts); err != nil {
		p.Close()
		return nil, err
	}
	if p.src, err = open(banmap.MapSrcBans); err != nil {
		p.Close()
		return nil, err
	}
	p.counters, _ = open(banmap.MapCounters)
	return p, nil
}

// readCounters 读 PERCPU_ARRAY 并按 CPU 求和。每个 key 返回一个 per-CPU 切片,
// 内核侧的 bump() 是无锁的 per-CPU 自增,所以求和才是总数。
func readCounters(m *ebpf.Map) []uint64 {
	if m == nil {
		return nil
	}
	out := make([]uint64, 0, banmap.CntMax)
	for i := 0; i < banmap.CntMax; i++ {
		var perCPU []uint64
		if err := m.Lookup(uint32(i), &perCPU); err != nil {
			return nil
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out = append(out, sum)
	}
	return out
}

// xdpAttachments 回答"哪块网卡上挂着 XDP 程序,prog id 是多少"。
//
// 这是唯一一条站在传统网络排障视角、有机会撞见 xdp-ban 的线索,等价于
// `ip link show` 里的 `prog/xdp id N`。查不到就返回 nil,由调用方说明。
func xdpAttachments() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		res, err := link.QueryPrograms(link.QueryOptions{
			Target: ifc.Index,
			Attach: ebpf.AttachXDP,
		})
		if err != nil || res == nil || len(res.Programs) == 0 {
			continue
		}
		ids := make([]string, 0, len(res.Programs))
		for _, p := range res.Programs {
			ids = append(ids, fmt.Sprintf("prog id %d", p.ID))
		}
		out = append(out, fmt.Sprintf("%s → %s", ifc.Name, strings.Join(ids, ", ")))
	}
	return out
}

// newInspector 打开 pin 并组装一次快照。调用方负责 Close。
func newInspector() (*inspector, *pinnedMaps, error) {
	p, err := openPinnedMaps()
	if err != nil {
		return nil, nil, err
	}
	boot, err := systemBootTime()
	if err != nil {
		p.Close()
		return nil, nil, fmt.Errorf("读取系统启动时刻(TTL 换算依赖它): %w", err)
	}
	return &inspector{
		global:      ebpfMap{p.global},
		targets:     ebpfMap{p.targets},
		src:         ebpfMap{p.src},
		counters:    readCounters(p.counters),
		uptime:      time.Since(boot),
		attachments: xdpAttachments(),
	}, p, nil
}

func runStatus(w io.Writer, errw io.Writer) int {
	in, p, err := newInspector()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	defer p.Close()
	if err := in.writeStatus(w); err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	return 0
}

// runWhy 的退出码有意义:0 = 没被封,2 = 正在被丢,1 = 查不了。
// 这样 `xdp-ban why 1.2.3.4 || echo blocked` 能直接用在脚本里。
func runWhy(w io.Writer, errw io.Writer, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(errw, "用法: xdp-ban why <ip>\n例如: xdp-ban why 203.0.113.9")
		return 1
	}
	addr, err := netip.ParseAddr(args[0])
	if err != nil {
		fmt.Fprintf(errw, "非法 IP %q: %v\n", args[0], err)
		return 1
	}

	in, p, err := newInspector()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	defer p.Close()

	if !addr.Is4() {
		fmt.Fprintf(w, "%s 是 IPv6。XDP 侧只处理 ETH_P_IP,IPv6 的包不会查任何 ban map ——\n"+
			"xdp-ban 不可能封住这个地址。\n", addr)
		return 0
	}

	dropping, err := in.writeWhy(w, addr)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	if dropping {
		return 2
	}
	return 0
}
