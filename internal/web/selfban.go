package web

// 这个文件只解决一件事:别让操作者把自己封掉。
//
// safety.Guard 保护的是 127.0.0.0/8、::1/128、0.0.0.0/32 和 DB 里的
// ProtectedTarget —— 没有一条覆盖"此刻正在点这个按钮的人的地址"。封掉自己
// 的 /24 是完全合法的一次提交,代价是同时失去唯一能解释原因、也唯一能回滚的
// 那个界面;而且规则不出现在 iptables -L / nft list ruleset /
// firewall-cmd --list-all 里,接手排障的人没有任何常用命令会指向 xdp-ban。
//
// 所以这里不是访问控制,是防手滑:命中就拦一次,把后果和补救路径讲清楚,
// 勾了确认再放行,并把这次确认记进审计。

import (
	"fmt"
	"net/netip"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// selfBanAckField 是"我已确认会切断自己的访问"复选框的表单字段名。
// 与配额那套 override_ack 分开:两者问的是完全不同的问题(影响面多大 vs.
// 你自己会不会掉线),混用会让审计里分不清操作者到底确认了什么。
const selfBanAckField = "self_ack"

// clientAddr 取"提交这次封禁的人的地址"。
//
// 用 ClientIP 而不是 RemoteIP:装了反向代理时 RemoteIP 恒为 127.0.0.1,
// 而 127.0.0.0/8 早已在硬保护集里 —— 这个检查就永远不会触发,等于白写。
// ClientIP 会读 X-Forwarded-For,确实可伪造,但这里是防手滑不是鉴权:
// 伪造的后果只是少一次提醒,而正确的后果是救回一次控制台之旅。
func clientAddr(c *gin.Context) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(c.ClientIP())
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// selfLockoutPrefix 在一批源前缀里找出覆盖操作者自身地址的那一条。
// 返回最先命中的前缀 —— 只需要一条就足以说明问题。
func selfLockoutPrefix(c *gin.Context, prefixes []netip.Prefix) (netip.Addr, netip.Prefix, bool) {
	me, ok := clientAddr(c)
	if !ok {
		return netip.Addr{}, netip.Prefix{}, false
	}
	for _, p := range prefixes {
		if p.Contains(me) {
			return me, p, true
		}
	}
	return me, netip.Prefix{}, false
}

// selfLockoutTarget 是单目标版本:target 是用户填的 IP 或 CIDR。
// 解析不出来时返回 false —— 非法输入由各自的校验路径去报错,这里不抢话。
func selfLockoutTarget(c *gin.Context, target string) (netip.Addr, netip.Prefix, bool) {
	p, err := parseAnyPrefix(target)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, false
	}
	return selfLockoutPrefix(c, []netip.Prefix{p})
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

// selfLockoutMsgGlobal 是全局封禁(对所有目标生效)的提示。
// 这是最坏的一档:提交并批准后,发起提交的那台机器立刻失去这个界面。
func selfLockoutMsgGlobal(me netip.Addr, hit netip.Prefix) string {
	return fmt.Sprintf("你正在从 %s 访问本界面,而这条规则的源前缀 %s 覆盖了这个地址。"+
		"批准后 XDP 会在网卡入口直接丢掉你自己的包:这个界面(唯一能看到原因、"+
		"也唯一能一键回滚的地方)会立刻失联,而 iptables -L / nft list ruleset / "+
		"firewall-cmd --list-all 里查不到任何痕迹。"+
		"届时只能到物理控制台上跑 `xdp-ban why %s` 定位、`xdp-ban status` 看全貌,"+
		"再用 `bpftool map delete pinned %s/%s key ...` 删键。"+
		"确认这是有意为之,请勾选“我已确认会切断自己的访问”后重新提交。",
		me, hit, me, banmap.PinDir, banmap.MapGlobalBans)
}

// selfLockoutMsgScoped 是定向封禁的提示:影响面小一档 —— 只切断你到 targetIP
// 的流量。但如果 targetIP 恰好是本机,后果和全局封禁一样,所以照样要说。
func selfLockoutMsgScoped(me netip.Addr, hit netip.Prefix, targetIP string) string {
	return fmt.Sprintf("你正在从 %s 访问本界面,而这条规则的源前缀 %s 覆盖了这个地址。"+
		"批准后你自己到 %s 的流量会被 XDP 丢掉;若 %s 就是本机,这个界面也会一起失联,"+
		"而且规则不会出现在 iptables/nft/firewalld 的任何列表里 —— "+
		"只能到控制台上用 `xdp-ban why %s` 和 `xdp-ban status` 排查。"+
		"确认这是有意为之,请勾选“我已确认会切断自己的访问”后重新提交。",
		me, hit, targetIP, targetIP, me)
}

func selfAcked(c *gin.Context) bool {
	return c.PostForm(selfBanAckField) != ""
}
