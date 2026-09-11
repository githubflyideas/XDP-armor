package livesession

import (
	"strings"
	"testing"
)

// 用真实格式的 /proc/net/tcp 片段喂解析器。这台开发机是 Windows,没有 /proc,
// 所以解析逻辑的正确性只能靠这种固定样本来钉死 —— 字节序反转错一位,封禁自保
// 就会保错地址,是最不能出错的一环。
func TestParseProcNetTCP_IPv4(t *testing.T) {
	// local 8080(0x1F90)上两条 ESTABLISHED:对端 203.0.113.9 和 10.0.0.5;
	// 一条 LISTEN(0A)必须被跳过;一条本地端口是 22(0x0016)的也要认;
	// 一条 st=06(非 ESTABLISHED)也要跳过。
	// 地址按小端存:203.0.113.9 = CB 00 71 09,反过来写成 097100CB。
	sample := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 901F0000:1F90 097100CB:D14E 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000
   1: 901F0000:1F90 0500000A:C3A2 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12300 1 0000
   3: 1600007F:0016 0F00A8C0:E0F1 01 00000000:00000000 00:00000000 00000000     0        0 12400 1 0000
   4: 901F0000:1F90 0800080A:1234 06 00000000:00000000 00:00000000 00000000  1000        0 12500 1 0000
`
	got := parseProcNetTCP(strings.NewReader(sample), map[int]bool{8080: true, 22: true})

	want := map[string]bool{
		"203.0.113.9":  true, // 8080 ESTABLISHED
		"10.0.0.5":     true, // 8080 ESTABLISHED
		"192.168.0.15": true, // 22 ESTABLISHED (0F00A8C0 -> C0 A8 00 0F)
	}
	if len(got) != len(want) {
		t.Fatalf("解析出 %d 个对端 %v,期望 %d 个 %v", len(got), got, len(want), want)
	}
	for _, a := range got {
		if !want[a.String()] {
			t.Errorf("不该出现的对端: %s(LISTEN 与非 ESTABLISHED 必须被过滤)", a)
		}
	}
}

func TestParseProcNetTCP_PortFilter(t *testing.T) {
	// 本地端口 9999(0x270F),不在关心列表里,必须被过滤掉。
	sample := `  sl  local_address rem_address   st ...
   0: 0F270000:270F 097100CB:D14E 01 00000000:00000000 00:00000000 00000000  1000 0 1 1 0
`
	if got := parseProcNetTCP(strings.NewReader(sample), map[int]bool{8080: true}); len(got) != 0 {
		t.Errorf("本地端口不在关心列表里,不该返回任何对端,实际 %v", got)
	}
}

func TestParseHexAddrPort_IPv6(t *testing.T) {
	// ::1 在 /proc/net/tcp6 里是 00000000000000000000000001000000。
	addr, port, ok := parseHexAddrPort("00000000000000000000000001000000:1F90")
	if !ok {
		t.Fatal("应能解析 IPv6")
	}
	if addr.String() != "::1" {
		t.Errorf("IPv6 解析 = %s,期望 ::1", addr)
	}
	if port != 8080 {
		t.Errorf("端口 = %d,期望 8080", port)
	}
}
