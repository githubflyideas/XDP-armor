package banmap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

const (
	MapGlobalBans  = "src_ban_global"
	MapTargetHosts = "target_hosts"
	MapSrcBans     = "src_ban"
	MapCounters    = "counters"
)

// PinDir 是四张 map 在 bpffs 上的 pin 目录。
//
// 之所以必须 pin:XDP 规则不出现在 iptables/nft/firewalld 的任何列表里,
// 排障时唯一的权威事实在 map 里。匿名 map 只有守护进程自己的 fd 能碰,
// 别的进程(`xdp-ban status`、`bpftool map dump`)都看不见,等于把唯一
// 的证据锁在进程内存里。pin 之后 map 有了文件系统上的名字,谁都能只读打开。
//
// 顺带的效果:进程重启后 pin 还在,未过期的封禁不会因为一次 `systemctl
// restart` 就漏出去。宿主重启会清掉整个 bpffs,那时 map 全空,由 reconcile
// 循环报漂移——这是有意的。
const PinDir = "/sys/fs/bpf/xdp-ban"

// PinnedMaps 是需要 pin 的 map 名单。counters 也在内:它是"内核此刻到底
// 在丢包吗"的唯一答案,而守护进程自己从不读它。
func PinnedMaps() []string {
	return []string{MapGlobalBans, MapTargetHosts, MapSrcBans, MapCounters}
}

const (
	GlobalKeySize = 8
	SrcKeySize    = 12
	TargetKeySize = 4
	ValueSize     = 24
)

const (
	CntDropped = iota
	CntPassed
	CntExpired
	CntNotTarget
	CntMax
)

// CounterLabel 给四个计数器一个能直接打给人看的名字,顺序必须与 xdp_filter.c
// 里的 enum 一致。
func CounterLabel(idx int) string {
	switch idx {
	case CntDropped:
		return "dropped 已丢弃"
	case CntPassed:
		return "passed 命中目标但放行"
	case CntExpired:
		return "expired 规则已过期放行"
	case CntNotTarget:
		return "not_target 非保护目标放行"
	}
	return fmt.Sprintf("counter[%d]", idx)
}

type Value struct {
	ExpiresAt uint64
	Hits      uint64
	RuleID    uint32
}

func EncodeValue(v Value) []byte {
	b := make([]byte, ValueSize)
	binary.LittleEndian.PutUint64(b[0:8], v.ExpiresAt)
	binary.LittleEndian.PutUint64(b[8:16], v.Hits)
	binary.LittleEndian.PutUint32(b[16:20], v.RuleID)

	return b
}

func DecodeValue(b []byte) (Value, error) {
	if len(b) < ValueSize {
		return Value{}, fmt.Errorf("ban_value 长度 %d,期望 %d", len(b), ValueSize)
	}
	return Value{
		ExpiresAt: binary.LittleEndian.Uint64(b[0:8]),
		Hits:      binary.LittleEndian.Uint64(b[8:16]),
		RuleID:    binary.LittleEndian.Uint32(b[16:20]),
	}, nil
}

func EncodeGlobalKey(prefix netip.Prefix) ([]byte, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("仅支持 IPv4 前缀,收到 %s", prefix)
	}
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return nil, fmt.Errorf("非法前缀长度 %d", bits)
	}

	p := prefix.Masked()
	a4 := p.Addr().As4()

	b := make([]byte, GlobalKeySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(bits))
	copy(b[4:8], a4[:])
	return b, nil
}

func DecodeGlobalKey(b []byte) (netip.Prefix, error) {
	if len(b) < GlobalKeySize {
		return netip.Prefix{}, fmt.Errorf("global_key 长度 %d,期望 %d", len(b), GlobalKeySize)
	}
	bits := binary.LittleEndian.Uint32(b[0:4])
	if bits > 32 {
		return netip.Prefix{}, fmt.Errorf("非法前缀长度 %d", bits)
	}
	var a4 [4]byte
	copy(a4[:], b[4:8])
	addr := netip.AddrFrom4(a4)
	return netip.PrefixFrom(addr, int(bits)), nil
}

func EncodeSrcKey(targetID uint32, prefix netip.Prefix) ([]byte, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("仅支持 IPv4 前缀,收到 %s", prefix)
	}
	srcBits := prefix.Bits()
	if srcBits < 0 || srcBits > 32 {
		return nil, fmt.Errorf("非法前缀长度 %d", srcBits)
	}

	p := prefix.Masked()
	a4 := p.Addr().As4()

	b := make([]byte, SrcKeySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(32+srcBits))
	binary.LittleEndian.PutUint32(b[4:8], targetID)
	copy(b[8:12], a4[:])
	return b, nil
}

func EncodeTargetKey(addr netip.Addr) ([]byte, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("目标仅支持 IPv4,收到 %s", addr)
	}
	a4 := addr.As4()
	b := make([]byte, TargetKeySize)
	copy(b, a4[:])
	return b, nil
}

// DecodeTargetKey 是 EncodeTargetKey 的逆运算。遍历 pin 住的 target_hosts
// 重建 target_id 映射时要用:进程重启后内存里的映射丢了,而 map 里还留着,
// 不读回来就会把同一个 target_id 分配给另一台主机,把两组规则搅在一起。
func DecodeTargetKey(b []byte) (netip.Addr, error) {
	if len(b) < TargetKeySize {
		return netip.Addr{}, fmt.Errorf("target_key 长度 %d,期望 %d", len(b), TargetKeySize)
	}
	var a4 [4]byte
	copy(a4[:], b[0:TargetKeySize])
	return netip.AddrFrom4(a4), nil
}

func EncodeTargetID(id uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, id)
	return b
}

func DecodeTargetID(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("target_id 长度 %d,期望 4", len(b))
	}
	return binary.LittleEndian.Uint32(b[0:4]), nil
}

// DecodeSrcKey 拆开 src_ban 的复合 key,返回 target_id 与源前缀。
// 注意 key 里存的 prefixlen 是 32+srcBits(前 32 位是精确匹配的 target_id),
// 这里减回去,还原成人能看的源前缀长度。
func DecodeSrcKey(b []byte) (uint32, netip.Prefix, error) {
	if len(b) < SrcKeySize {
		return 0, netip.Prefix{}, fmt.Errorf("src_key 长度 %d,期望 %d", len(b), SrcKeySize)
	}
	raw := binary.LittleEndian.Uint32(b[0:4])
	if raw < 32 || raw > 64 {
		return 0, netip.Prefix{}, fmt.Errorf("非法复合前缀长度 %d,期望 32..64", raw)
	}
	tid := binary.LittleEndian.Uint32(b[4:8])
	var a4 [4]byte
	copy(a4[:], b[8:12])
	return tid, netip.PrefixFrom(netip.AddrFrom4(a4), int(raw-32)), nil
}

func KtimeDeadline(bootTime time.Time, now time.Time, ttlSecs int64) uint64 {
	if ttlSecs <= 0 {
		return 0
	}
	uptime := now.Sub(bootTime)
	if uptime < 0 {
		uptime = 0
	}
	return uint64(uptime) + uint64(ttlSecs)*uint64(time.Second)
}

// TTLState 是一条 map 记录相对当前 uptime 的三种状态。
type TTLState int

const (
	// TTLPermanent:expires_at==0,内核永不放行。
	TTLPermanent TTLState = iota
	// TTLLive:未到期,内核正在丢包。
	TTLLive
	// TTLExpired:已到期。键还留在 map 里 —— XDP 侧只在查到时比对时间然后
	// 放行,不会自己删键。所以"map 里有这条"不等于"这个 IP 正在被封",
	// 排障时必须把两者分开说,否则会得出完全相反的结论。
	TTLExpired
)

// ClassifyTTL 把 map 里的 ktime 到期时刻换算成人能读的剩余时间。
// uptime 取 time.Since(systemBootTime()),与写入时 KtimeDeadline 用的基准一致。
func ClassifyTTL(expiresAt uint64, uptime time.Duration) (TTLState, time.Duration) {
	if expiresAt == 0 {
		return TTLPermanent, 0
	}
	if uptime < 0 {
		uptime = 0
	}
	left := int64(expiresAt) - int64(uptime)
	if left <= 0 {
		return TTLExpired, time.Duration(-left)
	}
	return TTLLive, time.Duration(left)
}

func ParseIPv4Prefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6: %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("非法地址或前缀: %q", s)
	}
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6: %q", s)
	}
	return netip.PrefixFrom(a, 32), nil
}
