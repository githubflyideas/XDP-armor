package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// demo 子命令:一条命令,在任何一台 Linux 上把"XDP 封禁在 netfilter 之前落下、
// 而 iptables 里查无此规则"这件事,自演一遍。
//
// 为什么要有它:xdp-ban 真正的分量(status/why 直接读内核 map、封禁对 iptables
// 隐形)平时埋在一条八步长路的最后 —— 装二进制、起服务、登录、提交、批准、下发、
// 直到有人把自己的网切了,才想起还有 why。demo 把这条路压成一条命令:自己造一对
// veth + netns 冒充"攻击者",把 XDP 挂到本机这一端,凭空按下一条封禁,从对端发包,
// 然后当场给你看 iptables 一片空白、内核计数器却在涨、why 能指名道姓。
//
// 它不碰你的业务网卡,不碰 SQLite,不走审批流 —— 只借 banmap 的编码原语把一条 ban
// 直接写进 map。默认全程用匿名(不 pin)map,跑完即拆,绝不动到正在运行的守护进程
// pin 的那几张 map;加 -hold 才 pin,并让你在另一个终端亲手跑 why。

const (
	demoNS       = "xdpban-demo"
	demoHostVeth = "xdpb-host"
	demoPeerVeth = "xdpb-peer"
	demoHostIP   = "203.0.113.1"
	demoPeerIP   = "203.0.113.9" // TEST-NET-3,文档保留段,不会撞真实业务地址
	demoCIDR     = "24"
	demoTTLSecs  = 3600
)

const demoUsage = `用法: xdp-ban demo [-hold]

一条命令,在本机自演一遍"XDP 封禁对 iptables 隐形":造 veth+netns 冒充攻击者,
把 XDP 挂到本机一端,凭空按下封禁,再从对端发包,当场对比 iptables(空)与
内核计数器(在涨)。需要 root 与 Linux。

  -hold   跑完不拆,把 map pin 到 ` + banmap.PinDir + ` 并阻塞,
          让你在另一个终端亲手跑 xdp-ban why / status;Ctrl-C 退出并清理。
  -fast   关掉每步之间的停顿(默认有停顿,方便录屏时看清)。
`

func runDemo(w, errw io.Writer, args []string) int {
	hold := false
	for _, a := range args {
		switch a {
		case "-hold", "--hold":
			hold = true
		case "-fast", "--fast":
			demoPaceEnabled = false
		case "-h", "-help", "--help":
			fmt.Fprint(w, demoUsage)
			return 0
		default:
			fmt.Fprintf(errw, "demo: 未知参数 %q\n\n%s", a, demoUsage)
			return 1
		}
	}

	if code := demoPreflight(errw, hold); code != 0 {
		return code
	}

	step(w, "0/6", "清理上一次可能残留的 demo 网络(幂等)")
	demoTeardownNet()

	step(w, "1/6", fmt.Sprintf("造一对 veth + netns:%s(本机,挂 XDP)↔ %s/%s(对端,冒充攻击者)",
		demoHostVeth, demoPeerIP, demoCIDR))
	if err := demoSetupNet(); err != nil {
		fmt.Fprintf(errw, "建 demo 网络失败: %v\n", err)
		demoTeardownNet()
		return 1
	}
	defer demoTeardownNet()

	step(w, "2/6", fmt.Sprintf("把 XDP 封禁程序以 generic 模式挂到 %s", demoHostVeth))
	d, err := demoAttach(demoHostVeth, hold)
	if err != nil {
		fmt.Fprintf(errw, "挂载 XDP 失败: %v\n", err)
		return 1
	}
	defer d.close()

	step(w, "3/6", fmt.Sprintf("封禁前:从对端 %s ping 本机 %s —— 应当通", demoPeerIP, demoHostIP))
	before := demoPing()
	fmt.Fprintf(w, "    %s\n", before.line)
	if !before.ok {
		fmt.Fprintf(w, "    ⚠ 封禁前就不通,说明 demo 网络没起对,后面的对比无意义 —— 先修网络。\n")
	}

	step(w, "4/6", fmt.Sprintf("凭空按下一条全局封禁 %s/32(TTL=%ds),直接写进内核 map,不走审批流",
		demoPeerIP, demoTTLSecs))
	if err := d.banGlobal(demoPeerIP, demoTTLSecs); err != nil {
		fmt.Fprintf(errw, "写封禁失败: %v\n", err)
		return 1
	}

	step(w, "5/6", fmt.Sprintf("封禁后:再从对端 %s ping 本机 %s —— 应当被 XDP 丢在网卡入口",
		demoPeerIP, demoHostIP))
	after := demoPing()
	fmt.Fprintf(w, "    %s\n", after.line)

	step(w, "6/6", "现在看两处互相矛盾的证据 —— 这正是 xdp-ban 存在的理由")
	demoReveal(w, d)

	if hold {
		return demoHold(w)
	}

	fmt.Fprintf(w, "\n收工,demo 网络已拆。想亲手玩:`sudo xdp-ban demo -hold`,\n"+
		"再在另一个终端 `sudo xdp-ban why %s` / `sudo xdp-ban status`。\n", demoPeerIP)
	return 0
}

// demoPaceEnabled 让每一步之间停顿一下 —— 这命令天生是给录屏看的,一口气刷完
// 没人看得清。-fast 关掉停顿(自测/CI 用)。
var demoPaceEnabled = true

func step(w io.Writer, tag, msg string) {
	if demoPaceEnabled {
		time.Sleep(1300 * time.Millisecond)
	}
	fmt.Fprintf(w, "\n[%s] %s\n", tag, msg)
}

// demoPreflight 拦下所有"跑不起来"的前置条件,给的都是能直接照做的下一步。
func demoPreflight(errw io.Writer, hold bool) int {
	if runtime.GOOS != "linux" {
		fmt.Fprintf(errw, "demo 只能在 Linux 上跑:XDP 是内核特性,%s 上没有。\n"+
			"把这个二进制拷到一台 Linux(或 `docker run` 一个)再跑。\n", runtime.GOOS)
		return 1
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(errw, "demo 需要 root:挂 XDP、建 netns/veth 都要 CAP_NET_ADMIN。\n"+
			"用 sudo 重试:sudo xdp-ban demo\n")
		return 1
	}
	if _, err := exec.LookPath("ip"); err != nil {
		fmt.Fprintf(errw, "demo 要用 iproute2 的 `ip` 命令造 netns/veth,但没找到它。\n"+
			"安装:apt-get install iproute2 / yum install iproute\n")
		return 1
	}
	if len(xdpFilterBytecode) == 0 {
		fmt.Fprintf(errw, "内嵌 eBPF bytecode 为空 —— 这个二进制是没跑 `make bpf` 就编出来的。\n"+
			"用 releases 里的官方二进制,或先 `make bpf && make build`。\n")
		return 1
	}
	if hold {
		if entries, _ := os.ReadDir(banmap.PinDir); len(entries) > 0 {
			fmt.Fprintf(errw, "demo -hold 要把 map pin 到 %s,但那里已经有东西 ——\n"+
				"多半是 xdp-ban 守护进程正在运行。为了不搅乱它,-hold 在此止步。\n"+
				"不带 -hold 的 `xdp-ban demo` 用匿名 map,任何时候都能安全跑。\n", banmap.PinDir)
			return 1
		}
	}
	return 0
}

func ipRun(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func demoSetupNet() error {
	steps := [][]string{
		{"netns", "add", demoNS},
		{"link", "add", demoHostVeth, "type", "veth", "peer", "name", demoPeerVeth},
		{"link", "set", demoPeerVeth, "netns", demoNS},
		{"addr", "add", demoHostIP + "/" + demoCIDR, "dev", demoHostVeth},
		{"link", "set", demoHostVeth, "up"},
		{"-n", demoNS, "addr", "add", demoPeerIP + "/" + demoCIDR, "dev", demoPeerVeth},
		{"-n", demoNS, "link", "set", demoPeerVeth, "up"},
		{"-n", demoNS, "link", "set", "lo", "up"},
	}
	for _, s := range steps {
		if err := ipRun(s...); err != nil {
			return err
		}
	}
	return nil
}

// demoTeardownNet 幂等:删 netns 会连带删掉里面的 peer veth,删 host veth 会连带
// 删掉整对。两条都可能本就不存在,忽略错误。
func demoTeardownNet() {
	_ = exec.Command("ip", "netns", "del", demoNS).Run()
	_ = exec.Command("ip", "link", "del", demoHostVeth).Run()
}

type pingResult struct {
	ok   bool
	line string
}

// demoPing 从对端 netns ping 本机。100% 丢包时 ping 退出码非 0 —— 那正是封禁后
// 我们要看到的结果,不当错误处理,只把它反映在 ok 上。
func demoPing() pingResult {
	out, err := exec.Command("ip", "netns", "exec", demoNS,
		"ping", "-c", "3", "-W", "1", "-i", "0.3", demoHostIP).CombinedOutput()
	return pingResult{ok: err == nil, line: demoPingSummary(string(out))}
}

func demoPingSummary(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "packet loss") {
			return strings.TrimSpace(ln)
		}
	}
	if t := strings.TrimSpace(out); t != "" {
		return t
	}
	return "(ping 无输出 —— 可能没装 iputils-ping)"
}

// demoMaps 持有 demo 这一轮加载的 collection、attach 的 link、以及要写/读的四张 map。
type demoMaps struct {
	global   *ebpf.Map
	targets  *ebpf.Map
	src      *ebpf.Map
	counters *ebpf.Map
	link     link.Link
	coll     *ebpf.Collection
	boot     time.Time
	pinned   bool
}

func (d *demoMaps) close() {
	if d.link != nil {
		d.link.Close()
	}
	if d.coll != nil {
		d.coll.Close()
	}
	// -hold 模式 pin 了 map,退出时连目录一起清掉,别把 demo 的假封禁留在 bpffs 上
	// 冒充真规则。非 pin 模式绝不碰 PinDir(那可能是守护进程的)。
	if d.pinned {
		_ = os.RemoveAll(banmap.PinDir)
	}
}

func demoAttach(iface string, pin bool) (*demoMaps, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpFilterBytecode))
	if err != nil {
		return nil, fmt.Errorf("load ebpf spec: %w", err)
	}

	coll, pinned, err := demoLoadCollection(spec, pin)
	if err != nil {
		return nil, err
	}

	fail := func(format string, a ...any) (*demoMaps, error) {
		if pinned {
			_ = os.RemoveAll(banmap.PinDir)
		}
		coll.Close()
		return nil, fmt.Errorf(format, a...)
	}

	prog := coll.Programs["xdp_filter"]
	if prog == nil {
		return fail("内嵌 bytecode 缺少 xdp_filter 程序 —— bytecode 与本程序版本不匹配")
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return fail("查找网卡 %q: %v", iface, err)
	}
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifc.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fail("attach XDP(generic 模式)到 %s: %v", iface, err)
	}
	boot, err := systemBootTime()
	if err != nil {
		lnk.Close()
		return fail("读取系统启动时刻(TTL 换算依赖它): %v", err)
	}

	d := &demoMaps{
		global:   coll.Maps[banmap.MapGlobalBans],
		targets:  coll.Maps[banmap.MapTargetHosts],
		src:      coll.Maps[banmap.MapSrcBans],
		counters: coll.Maps[banmap.MapCounters],
		link:     lnk, coll: coll, boot: boot, pinned: pinned,
	}
	if d.global == nil || d.counters == nil {
		d.close()
		return nil, fmt.Errorf("内嵌 bytecode 缺少必要的 map(%s / %s)",
			banmap.MapGlobalBans, banmap.MapCounters)
	}
	return d, nil
}

// demoLoadCollection 按需 pin。非 pin 是默认,匿名 map 只有本进程可见,绝对安全;
// pin(仅 -hold)让另一个终端的 status/why 能读到,代价是要独占 PinDir。
func demoLoadCollection(spec *ebpf.CollectionSpec, pin bool) (*ebpf.Collection, bool, error) {
	if !pin {
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return nil, false, fmt.Errorf("加载 eBPF: %w", err)
		}
		return coll, false, nil
	}
	if err := os.MkdirAll(banmap.PinDir, 0o700); err != nil {
		return nil, false, fmt.Errorf("建 pin 目录 %s: %w", banmap.PinDir, err)
	}
	for _, name := range banmap.PinnedMaps() {
		if ms, ok := spec.Maps[name]; ok {
			ms.Pinning = ebpf.PinByName
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: banmap.PinDir},
	})
	if err != nil {
		_ = os.RemoveAll(banmap.PinDir)
		return nil, false, fmt.Errorf("加载并 pin eBPF 到 %s: %w", banmap.PinDir, err)
	}
	return coll, true, nil
}

// banGlobal 把一条全局封禁直接写进内核 map —— 复用的正是执行器落盘时用的那套
// 编码原语(banmap.EncodeGlobalKey / EncodeValue / KtimeDeadline),所以 demo
// 里丢包的判定和真实封禁逐字节一致,不是另搭的一套假逻辑。
func (d *demoMaps) banGlobal(ip string, ttlSecs int64) error {
	prefix, err := banmap.ParseIPv4Prefix(ip)
	if err != nil {
		return err
	}
	key, err := banmap.EncodeGlobalKey(prefix)
	if err != nil {
		return err
	}
	val := banmap.EncodeValue(banmap.Value{
		ExpiresAt: banmap.KtimeDeadline(d.boot, time.Now(), ttlSecs),
		RuleID:    99, // demo 专用 rule_id,一眼能认出这不是真规则
	})
	return d.global.Put(key, val)
}

// demoReveal 把两处证据摆在一起:传统防火墙查无此规则,内核 XDP 侧却明明白白
// 在丢包。复用的是 status/why 那套 inspector,demo 看到的输出与真机排障一字不差。
func demoReveal(w io.Writer, d *demoMaps) {
	fmt.Fprintf(w, "\n  ── 证据一:传统防火墙视角,查无此规则 ──\n")
	demoShowFirewallClean(w)

	fmt.Fprintf(w, "\n  ── 证据二:内核 XDP 侧,规则和丢包都在这儿 ──\n\n")
	in := &inspector{
		global:      ebpfMap{d.global},
		targets:     ebpfMap{d.targets},
		src:         ebpfMap{d.src},
		counters:    readCounters(d.counters),
		uptime:      time.Since(d.boot),
		attachments: xdpAttachments(),
	}
	if _, err := in.writeWhy(w, netip.MustParseAddr(demoPeerIP)); err != nil {
		fmt.Fprintf(w, "  (why 失败: %v)\n", err)
	}
	in.writeCounters(w)
}

// demoShowFirewallClean 跑 iptables/nft 并证明它们的输出里根本没有被封的地址。
// 没装这两个工具反而更点题:装了也查不到,何况没装。
func demoShowFirewallClean(w io.Writer) {
	checks := []struct {
		label string
		argv  []string
	}{
		{"iptables -S", []string{"iptables", "-S"}},
		{"nft list ruleset", []string{"nft", "list", "ruleset"}},
	}
	shown := false
	for _, c := range checks {
		if _, err := exec.LookPath(c.argv[0]); err != nil {
			continue
		}
		out, _ := exec.Command(c.argv[0], c.argv[1:]...).CombinedOutput()
		shown = true
		if strings.Contains(string(out), demoPeerIP) {
			fmt.Fprintf(w, "  %-18s 竟提到了 %s(意外 —— demo 只写了 XDP map)\n", c.label, demoPeerIP)
		} else {
			fmt.Fprintf(w, "  %-18s 全文没有 %s —— 这条封禁在这里彻底隐形\n", c.label, demoPeerIP)
		}
	}
	if !shown {
		fmt.Fprintf(w, "  (没装 iptables/nft —— 但这恰是重点:装了也查不到这条规则)\n")
	}
}

// demoHold 保持 demo 网络与 pin 住的 map 存活,阻塞到 Ctrl-C。退出后由调用方的
// defer(d.close / demoTeardownNet)统一清理:拆网络、卸 XDP、删 pin。
func demoHold(w io.Writer) int {
	fmt.Fprintf(w, "\n[-hold] map 已 pin 到 %s,demo 网络仍在。到另一个终端试试:\n", banmap.PinDir)
	fmt.Fprintf(w, "    sudo xdp-ban why %s        # 它读的就是这几张 pin 住的 map\n", demoPeerIP)
	fmt.Fprintf(w, "    sudo xdp-ban status\n")
	fmt.Fprintf(w, "    sudo iptables -S | grep %s   # 一无所获\n", demoPeerIP)
	fmt.Fprintf(w, "\n按 Ctrl-C 退出并清理(拆网络、卸 XDP、删 pin)。\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintf(w, "\n收到退出信号,清理中……\n")
	return 0
}
