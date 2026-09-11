// Package livesession 回答一个很具体的问题:此刻有哪些机器正连着本机的某个
// 端口?数据来自内核 socket 表(/proc/net/tcp、/proc/net/tcp6)—— 也就是
// `netstat -tn` / `ss -tn` 背后那张表,只是我们直接解析,不 shell 出去。
//
// 为什么对 xdp-ban 重要:XDP 按源 IP 在网卡入口丢包。一条封禁真正会切断的,
// 正是那些以某个源地址连到本机的 TCP 连接。而"正在 web 上改规则的 admin"、
// "还 SSH 着的运维",都在这张表里以 ESTABLISHED 出现,对端地址就是 XDP 一旦
// 封禁就会切掉的地址。
//
// 这比 HTTP 层的 ClientIP 可靠:X-Forwarded-For 能伪造、反向代理会把 RemoteIP
// 抹成 127.0.0.1,而 socket 表是 L3/L4 的事实,伪造头骗不了它。代价是它看到的
// 是"到达本机的那一跳"——直连时就是对端真实地址,前面挡着反代时则是反代的地址
// (仍然 L3 正确:XDP 真要切,切的就是这一跳)。
package livesession

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// procTCPEstablished 是 /proc/net/tcp 里 TCP_ESTABLISHED 状态的十六进制码。
// 我们只认已建立的连接:LISTEN(0A)、TIME_WAIT 之类都不是"某人正连着"。
const procTCPEstablished = "01"

// Peers 返回本机上、本地端口落在 wantPorts 里、且处于 ESTABLISHED 的所有连接的
// 对端地址(去重)。读不到 /proc(非 Linux、被沙箱挡住)时返回 nil —— 调用方
// 应把它当作"拿不到这个信号",降级到别的判断,而不是报错。
func Peers(wantPorts []int) []netip.Addr {
	if len(wantPorts) == 0 {
		return nil
	}
	want := make(map[int]bool, len(wantPorts))
	for _, p := range wantPorts {
		want[p] = true
	}

	var all []netip.Addr
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		all = append(all, parseProcNetTCP(f, want)...)
		f.Close()
	}
	return dedup(all)
}

// parseProcNetTCP 解析一张 /proc/net/tcp[6] 的内容,抽出本地端口命中 want、
// 状态为 ESTABLISHED 的连接的对端地址。抽成独立函数是为了能用固定文本喂测试,
// 不依赖真机(这台开发机是 Windows,根本没有 /proc)。
func parseProcNetTCP(r io.Reader, want map[int]bool) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// 典型数据行:
		//   1: 0100007F:1F90 0100007F:C3A2 01 00000000:00000000 ...
		//   [0]=sl [1]=local_addr:port [2]=rem_addr:port [3]=st
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] != procTCPEstablished {
			continue // 跳过表头(st 那列是 "st")和非 ESTABLISHED 连接
		}
		_, lport, ok := parseHexAddrPort(fields[1])
		if !ok || !want[int(lport)] {
			continue
		}
		rip, _, ok := parseHexAddrPort(fields[2])
		if !ok {
			continue
		}
		out = append(out, rip.Unmap())
	}
	return out
}

// parseHexAddrPort 解析 /proc/net/tcp 里 "ADDR:PORT" 那种十六进制字段。
// 地址按 4 字节小端字(little-endian word)存:IPv4 是 1 个字,IPv6 是 4 个字,
// 每个字内部字节序是反的,要逐字反转还原。端口是大端十六进制,直接解析。
func parseHexAddrPort(field string) (netip.Addr, uint16, bool) {
	i := strings.LastIndexByte(field, ':')
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	ipHex, portHex := field[:i], field[i+1:]

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}

	raw, err := hex.DecodeString(ipHex)
	if err != nil {
		return netip.Addr{}, 0, false
	}

	switch len(raw) {
	case 4:
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), uint16(port), true
	case 16:
		var b [16]byte
		for w := 0; w < 16; w += 4 {
			b[w], b[w+1], b[w+2], b[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
		}
		return netip.AddrFrom16(b), uint16(port), true
	default:
		return netip.Addr{}, 0, false
	}
}

func dedup(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	seen := make(map[netip.Addr]bool, len(addrs))
	out := addrs[:0]
	for _, a := range addrs {
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}
