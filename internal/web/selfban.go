package web

// 这个文件只解决一件事:别让操作者把自己封掉。
//
// safety.Guard 保护的是 127.0.0.0/8、::1/128、0.0.0.0/32 和 DB 里的
// ProtectedTarget —— 没有一条覆盖"此刻正在操作规则的那台机器的地址"。封掉自己
// 的 /24 是完全合法的一次提交,代价是同时失去唯一能解释原因、也唯一能回滚的
// 那个界面;而且规则不出现在 iptables -L / nft list ruleset /
// firewall-cmd --list-all 里,接手排障的人没有任何常用命令会指向 xdp-ban。
//
// 判据的核心是那句话:只要你还能连上这台机器操作,就不危险 —— 因为能回退。
// 真正要拦的,是"这条封禁会切掉你此刻正用着的这条连接"。所以除了 HTTP 层不可靠
// 的 ClientIP,我们还直接读内核 socket 表(livesession),把"正连着 web/SSH 的
// 对端地址"也算进"操作者自己"。命中就拦一次,勾了"我确认能从别处回退"再放行,
// 并把这次确认记进审计。

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/banmap"
	"github.com/xdpban/xdp-ban/internal/livesession"
)

// selfBanAckField 是"我确认会切断自己、且能从别处回退"复选框的表单字段名。
// 与配额那套 override_ack 分开:两者问的是完全不同的问题(影响面多大 vs.
// 你会不会把自己此刻的连接切了),混用会让审计里分不清操作者确认了什么。
const selfBanAckField = "self_ack"

// sessionPeers 返回"此刻正连着本机管理端口(web + SSH)的对端地址"。
// 抽成变量是为了测试能注入固定值 —— 真实现读 /proc,这台开发机(Windows)和
// 单元测试都拿不到真数据,不注入就永远测不到 socket 表这条路。
var sessionPeers = func() []netip.Addr {
	if runtime.GOOS != "linux" {
		return nil // 只有 Linux 有 XDP,也只有 Linux 的 /proc/net/tcp 是这个格式
	}
	return livesession.Peers(protectPorts())
}

// protectPorts 是"连着它就算正在操作/还能回退本机、因而不能被自己封掉"的本地
// 端口集合:xdp-ban 自己的监听端口(默认 8080,即正在改规则的会话)+ SSH 22
// (即失联后还能登上去回滚的那条路)。
func protectPorts() []int {
	ports := []int{22}
	if p := listenPort(); p != 0 {
		ports = append(ports, p)
	}
	return ports
}

// listenPort 从 XDPBAN_ADDR 里取出监听端口。取不到就退回 8080 —— 那是默认监听
// 端口,宁可多保护一个常见端口,也别因为解析失败而漏掉"正在改规则的会话"。
func listenPort() int {
	addr := envOr("XDPBAN_ADDR", ":8080")
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 8080
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 8080
	}
	return p
}

// selfHit 记录一次自封命中:哪个地址、被哪条前缀盖住、以及是靠哪种信号发现的。
// FromSession=true 表示来自内核 socket 表(可靠,伪造不了);false 表示只靠
// HTTP 层的 ClientIP 判断(直连准、反代/伪造 XFF 时不可靠)。措辞据此调整。
type selfHit struct {
	Addr        netip.Addr
	Prefix      netip.Prefix
	FromSession bool
}

// clientAddr 取"提交这次封禁的 HTTP 请求来源地址"。
//
// 用 ClientIP 而不是 RemoteIP:装了反向代理时 RemoteIP 恒为 127.0.0.1,
// 而 127.0.0.0/8 早已在硬保护集里 —— 这个信号就永远不会触发,等于白读。
// ClientIP 会读 X-Forwarded-For,确实可伪造;但它只是 socket 表之外的补充信号,
// 伪造的后果只是少一次提醒,真正可靠的那条路走 sessionPeers。
func clientAddr(c *gin.Context) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(c.ClientIP())
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// detectSelfLockout 在一批源前缀里找出会切断"操作者自己"的那一条。先查 socket
// 表里的活跃对端(可靠信号优先),再退回 ClientIP。任一命中即返回,一条就够。
func detectSelfLockout(c *gin.Context, prefixes []netip.Prefix) (selfHit, bool) {
	peers := sessionPeers()
	for _, p := range prefixes {
		for _, peer := range peers {
			if p.Contains(peer) {
				return selfHit{Addr: peer, Prefix: p, FromSession: true}, true
			}
		}
	}
	if me, ok := clientAddr(c); ok {
		for _, p := range prefixes {
			if p.Contains(me) {
				return selfHit{Addr: me, Prefix: p}, true
			}
		}
	}
	return selfHit{}, false
}

// selfLockoutTarget 是单目标版本:target 是用户填的 IP 或 CIDR。
// 解析不出来时返回 false —— 非法输入由各自的校验路径去报错,这里不抢话。
func selfLockoutTarget(c *gin.Context, target string) (selfHit, bool) {
	p, err := parseAnyPrefix(target)
	if err != nil {
		return selfHit{}, false
	}
	return detectSelfLockout(c, []netip.Prefix{p})
}

// parseAnyPrefix 把 "1.2.3.4" 或 "1.2.3.0/24" 统一成前缀,IPv4/IPv6 都收。
// 不复用 banmap.ParseIPv4Prefix:那个会拒 IPv6,而这里宁可多提醒一次 ——
// 提交表单允许填 IPv6,拒绝发生在更后面的执行层。
func parseAnyPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}

// hitLead 是自封提示的开头一句,点明"凭什么说这地址是你自己的"。
// socket 表命中时措辞更硬(这是事实),ClientIP 命中时留有余地(可能不准)。
func hitLead(h selfHit) string {
	if h.FromSession {
		return fmt.Sprintf("检测到你此刻正从 %s 连着本机的管理端口(web / SSH),"+
			"而这条规则的源前缀 %s 覆盖了这个地址。", h.Addr, h.Prefix)
	}
	return fmt.Sprintf("你正在从 %s 访问本界面(据请求来源判断),"+
		"而这条规则的源前缀 %s 覆盖了这个地址。", h.Addr, h.Prefix)
}

// selfLockoutMsgGlobal 是全局封禁(对所有目标生效)的提示。
// 这是最坏的一档:提交并批准后,发起提交的那台机器立刻失去这个界面。
func selfLockoutMsgGlobal(h selfHit) string {
	return hitLead(h) + fmt.Sprintf(
		"批准后 XDP 会在网卡入口直接丢掉你自己的包:这个界面(唯一能看到原因、"+
			"也唯一能一键回滚的地方)会立刻失联,而 iptables -L / nft list ruleset / "+
			"firewall-cmd --list-all 里查不到任何痕迹。"+
			"只有当你还留着另一条能连上这台机器的路(物理控制台,或另一个不在封禁范围内的地址),"+
			"才能用 `xdp-ban why %s` 定位、`xdp-ban status` 看全貌,"+
			"再用 `bpftool map delete pinned %s/%s key ...` 删键回滚。"+
			"确认你有别的回退路径、这是有意为之,请勾选“我确认会切断自己、且能从别处回退”后重新提交。",
		h.Addr, banmap.PinDir, banmap.MapGlobalBans)
}

// selfLockoutMsgScoped 是定向封禁的提示:影响面小一档 —— 只切断你到 targetIP
// 的流量。但如果 targetIP 恰好是本机,后果和全局封禁一样,所以照样要说。
func selfLockoutMsgScoped(h selfHit, targetIP string) string {
	return hitLead(h) + fmt.Sprintf(
		"批准后你自己到 %s 的流量会被 XDP 丢掉;若 %s 就是本机,这个界面也会一起失联,"+
			"而且规则不会出现在 iptables/nft/firewalld 的任何列表里 —— "+
			"只要还留着另一条路(控制台或别的地址),就能用 `xdp-ban why %s` 和 `xdp-ban status` 排查回滚。"+
			"确认你有别的回退路径、这是有意为之,请勾选“我确认会切断自己、且能从别处回退”后重新提交。",
		targetIP, targetIP, h.Addr)
}

func selfAcked(c *gin.Context) bool {
	return c.PostForm(selfBanAckField) != ""
}
