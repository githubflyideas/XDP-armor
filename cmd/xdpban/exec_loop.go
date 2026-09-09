package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/banmap"
	"github.com/xdpban/xdp-ban/internal/model"
)

type BanPayload struct {
	Target  string `json:"target"`
	TTLSecs int64  `json:"ttl_secs"`
	NodeID  string `json:"node_id"`
	ReqID   uint   `json:"req_id"`
	BanID   string `json:"ban_id"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`

	ScopedTarget string   `json:"scoped_target,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
}

func startExecutor(db *gorm.DB, iface string) (*banMaps, func()) {
	if len(xdpFilterBytecode) == 0 {
		log.Fatalf("嵌入的 eBPF bytecode 为空:请先运行 `make bpf` 编译 bpf/xdp_filter.c,再重新构建本程序")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpFilterBytecode))
	if err != nil {
		log.Fatalf("load ebpf spec: %v", err)
	}

	coll, pinned, err := newPinnedCollection(spec)
	if err != nil {
		log.Fatalf("create ebpf collection: %v", err)
	}

	maps, err := resolveMaps(coll)
	if err != nil {
		coll.Close()
		log.Fatalf("%v", err)
	}
	log.Printf("✓ eBPF map 就绪: %s / %s / %s",
		banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans)
	if pinned {
		log.Printf("✓ map 已 pin 到 %s —— 排障用 `xdp-ban status` / `xdp-ban why <ip>`",
			banmap.PinDir)
	}

	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		log.Fatalf("查找网卡 %q 失败: %v", iface, err)
	}

	prog := coll.Programs["xdp_filter"]
	if prog == nil {
		coll.Close()
		log.Fatalf("内嵌 bytecode 缺少 xdp_filter 程序 —— bytecode 与本程序版本不匹配")
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifc.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		log.Fatalf("attach XDP(generic 模式)到 %s 失败: %v ——"+
			"常见原因:权限不足(需 root/CAP_NET_ADMIN)、内核过旧不支持 generic XDP、"+
			"或已有另一个 XDP 程序占用该网卡", iface, err)
	}
	log.Printf("✓ XDP 封禁程序已以 generic 模式挂载到 %s", iface)

	boot, err := systemBootTime()
	if err != nil {
		lnk.Close()
		coll.Close()
		log.Fatalf("读取系统启动时刻(TTL 换算依赖它): %v", err)
	}
	log.Printf("✓ 系统启动于 %s,TTL 将换算为 ktime 基准", boot.Format(time.RFC3339))

	bm := newBanMaps(
		ebpfMap{maps[banmap.MapGlobalBans]},
		ebpfMap{maps[banmap.MapTargetHosts]},
		ebpfMap{maps[banmap.MapSrcBans]},
		boot,
	)

	// pin 之后 map 会跨进程重启存活,内存里的 target_id 映射却不会。
	// 不读回来就会把 target_id=1 重新分配给另一台主机,让旧规则突然作用在
	// 新目标上 —— 这是 pin 带来的唯一新风险,在这里一次性消掉。
	if n, err := bm.restoreTargets(); err != nil {
		log.Printf("WARN 重建 target_id 映射失败: %v ——"+
			"定向封禁的回滚可能找不到对应键,建议清空 %s/%s 后重启",
			err, banmap.PinDir, banmap.MapTargetHosts)
	} else if n > 0 {
		log.Printf("✓ 从 %s 恢复了 %d 个目标主机的 target_id 映射(上次进程留下的)",
			banmap.MapTargetHosts, n)
	}

	closeFn := func() {
		lnk.Close()
		coll.Close()
	}
	return bm, closeFn
}

// newPinnedCollection 加载 collection 并把四张 map pin 到 banmap.PinDir。
//
// pin 失败不致命:bpffs 没挂载的宿主上照样要能封禁,只是丢掉 `xdp-ban status`
// 这条排障路径。所以降级继续,但把补救命令原样打进日志 —— 这正是本次要解决的
// "出了事查不出来"的场景,不能悄悄失败。
func newPinnedCollection(spec *ebpf.CollectionSpec) (*ebpf.Collection, bool, error) {
	if err := os.MkdirAll(banmap.PinDir, 0o700); err != nil {
		log.Printf("WARN 无法创建 pin 目录 %s: %v —— map 将不被 pin,"+
			"`xdp-ban status` / `xdp-ban why` 与 bpftool 都看不到规则。"+
			"补救:mount -t bpf bpf /sys/fs/bpf", banmap.PinDir, err)
		coll, err := ebpf.NewCollection(spec)
		return coll, false, err
	}

	for _, name := range banmap.PinnedMaps() {
		ms, ok := spec.Maps[name]
		if !ok {
			continue
		}
		ms.Pinning = ebpf.PinByName
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: banmap.PinDir},
	})
	if err == nil {
		return coll, true, nil
	}

	// 最常见的失败是上次留下的 pin 与本次 spec 不兼容(改过 map 定义后重新
	// make bpf)。这种情况下报出确切的清理命令,比让人猜 EINVAL 有用得多。
	log.Printf("WARN 带 pin 加载失败: %v —— 退回不 pin 的加载方式。"+
		"若是升级后 map 定义变了,rm -rf %s 再重启即可(会清掉存活的封禁,"+
		"reconcile 循环随后会把漂移报出来)", err, banmap.PinDir)

	for _, name := range banmap.PinnedMaps() {
		if ms, ok := spec.Maps[name]; ok {
			ms.Pinning = ebpf.PinNone
		}
	}
	coll, err2 := ebpf.NewCollection(spec)
	return coll, false, err2
}

func runExecutorLoop(ctx context.Context, db *gorm.DB, bm *banMaps, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pollAndExecute(db, bm)
		case <-ctx.Done():
			log.Printf("执行器循环收到停止信号,退出")
			return
		}
	}
}

// runReconcileLoop 是与执行轮询独立的、更粗粒度的回读核对循环——
// 两者语义不同(一个是"有活干就干",一个是"定期抽查有没有跑偏"),
// 故意不共用同一个 ticker,避免混淆。只记录 drift,不自动修复。
func runReconcileLoop(ctx context.Context, db *gorm.DB, bm *banMaps, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			drifts := reconcile(db, bm)
			for _, d := range drifts {
				log.Printf("WARN reconcile: %s", d)
			}
		case <-ctx.Done():
			log.Printf("回读核对循环收到停止信号,退出")
			return
		}
	}
}

func pollAndExecute(db *gorm.DB, bm *banMaps) {
	var dispatches []model.Dispatch
	if err := db.Where("state = ?", "pending").Limit(50).Find(&dispatches).Error; err != nil {
		log.Printf("查询待执行 dispatch 失败: %v", err)
		return
	}
	if len(dispatches) == 0 {
		return
	}
	log.Printf("获取 %d 条待执行指令", len(dispatches))

	for _, d := range dispatches {
		var payload BanPayload
		if err := json.Unmarshal([]byte(d.Payload), &payload); err != nil {
			log.Printf("指令 #%d payload 解析失败: %v", d.ID, err)
			markFailed(db, &d, fmt.Sprintf("parse error: %v", err))
			continue
		}

		log.Printf("执行指令 #%d: %s", d.ID, describePayload(&payload))

		if err := bm.Apply(&payload); err != nil {
			log.Printf("指令 #%d 执行失败: %v", d.ID, err)
			markFailed(db, &d, err.Error())
			continue
		}

		markAcked(db, &d)
		log.Printf("指令 #%d 执行成功", d.ID)
	}
}

func describePayload(p *BanPayload) string {
	if p.ScopedTarget != "" {
		return fmt.Sprintf("范围封禁 %d 条源前缀 → %s (TTL=%ds)",
			len(p.Prefixes), p.ScopedTarget, p.TTLSecs)
	}
	return fmt.Sprintf("全局封禁 %s (TTL=%ds)", p.Target, p.TTLSecs)
}

func markAcked(db *gorm.DB, d *model.Dispatch) {
	now := time.Now()
	if err := db.Model(d).Updates(map[string]any{
		"state":    "acked",
		"acked_at": now,
	}).Error; err != nil {
		log.Printf("指令 #%d 标记 acked 失败: %v", d.ID, err)
		return
	}
	_ = model.WriteAudit(db, nil, "executor", "Dispatch", strconv.FormatUint(uint64(d.ID), 10), "acked", "")
}

func markFailed(db *gorm.DB, d *model.Dispatch, errMsg string) {
	if err := db.Model(d).Updates(map[string]any{
		"state":      "failed",
		"last_error": errMsg,
		"attempts":   d.Attempts + 1,
	}).Error; err != nil {
		log.Printf("指令 #%d 标记 failed 失败: %v", d.ID, err)
		return
	}
	_ = model.WriteAudit(db, nil, "executor", "Dispatch", strconv.FormatUint(uint64(d.ID), 10), "failed", errMsg)
}

func resolveMaps(coll *ebpf.Collection) (map[string]*ebpf.Map, error) {
	want := []string{banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans}
	out := make(map[string]*ebpf.Map, len(want))
	var missing []string
	for _, name := range want {
		m := coll.Maps[name]
		if m == nil {
			missing = append(missing, name)
			continue
		}
		out[name] = m
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("eBPF bytecode 中缺少 map: %s —— "+
			"bytecode 与本程序版本不匹配,请重新 `make bpf && make build`",
			strings.Join(missing, ", "))
	}
	return out, nil
}

func systemBootTime() (time.Time, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return time.Time{}, fmt.Errorf("/proc/uptime 格式异常: %q", string(b))
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析 uptime %q: %w", fields[0], err)
	}
	return time.Now().Add(-time.Duration(secs * float64(time.Second))), nil
}
