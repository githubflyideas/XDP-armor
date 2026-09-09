package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/banmap"
	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/prefixdb"
	"github.com/xdpban/xdp-ban/internal/web"
)

var Version = "dev"

// usage 里必须提到 status/why。XDP 规则不出现在 iptables/nft/firewalld 的任何
// 列表里,`xdp-ban -h` 是运维手里唯一还能自己发现这两条排障命令的地方。
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "xdp-ban %s —— 基于 XDP 的封禁执行器\n\n", Version)
	fmt.Fprintf(out, "用法:\n")
	fmt.Fprintf(out, "  xdp-ban -iface <ifname>   启动守护进程(Web + 执行器)\n")
	fmt.Fprintf(out, "  xdp-ban status            打印内核侧的封禁快照(只读,不需要 -iface)\n")
	fmt.Fprintf(out, "  xdp-ban why <ip>          回答某个 IP 此刻是否正被 XDP 丢包\n")
	fmt.Fprintf(out, "  xdp-ban version           打印版本号\n\n")
	fmt.Fprintf(out, "排障提示: XDP 挂在 netfilter 之前,规则永远不会出现在 iptables -L /\n")
	fmt.Fprintf(out, "nft list ruleset / firewall-cmd --list-all 里。要看真实生效的规则,\n")
	fmt.Fprintf(out, "只有 `xdp-ban status`(或 bpftool map dump pinned %s/...)。\n\n", banmap.PinDir)
	fmt.Fprintf(out, "守护进程参数:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage

	// 子命令在 flag.Parse 之前分流:status/why 是只读诊断,不该被"必须指定
	// -iface"挡住 —— 需要它们的时候,往往正是守护进程起不来或 Web 进不去的时候。
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "status":
			os.Exit(runStatus(os.Stdout, os.Stderr))
		case "why":
			os.Exit(runWhy(os.Stdout, os.Stderr, os.Args[2:]))
		case "version", "-version", "--version":
			fmt.Printf("xdp-ban %s\n", Version)
			os.Exit(0)
		case "help":
			usage()
			os.Exit(0)
		}
	}

	dbPath := env("XDPBAN_DB", "xdpban.db")
	addr := env("XDPBAN_ADDR", ":8080")

	ifaceFlag := flag.String("iface", "", "XDP 封禁程序挂载的网卡(业务口,不是采样镜像口)")
	pollInterval := flag.Duration("poll-interval", 5*time.Second, "扫描待执行 dispatch 的间隔")
	flag.Parse()

	iface := *ifaceFlag
	if iface == "" {
		iface = os.Getenv("XDPBAN_IFACE")
	}
	if iface == "" {
		log.Fatalf("必须指定 XDP 封禁网卡:-iface <ifname> 或环境变量 XDPBAN_IFACE。" +
			"这是执行层生效的前提,没有它封禁只会停留在审批记录里,不会真正拦截流量。")
	}

	log.Printf("xdp-ban %s starting", Version)

	db, err := model.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	seed(db)

	loadPrefixDB()

	bm, closeXDP := startExecutor(db, iface)
	execCtx, cancelExec := context.WithCancel(context.Background())
	go runExecutorLoop(execCtx, db, bm, *pollInterval)
	go runReconcileLoop(execCtx, db, bm, 5*time.Minute)

	// gin 不设模式就默认 debug:启动时把整张路由表连同 handler 的完全限定名
	// 打一屏,再警告你切 release,每个请求还多走一层 debug 逻辑。生产不需要这些,
	// 所以默认就按 release 跑;真要排障时显式 GIN_MODE=debug 拿回来。
	// 只在环境变量为空时才覆盖 —— gin 自己在 init() 里就读了 GIN_MODE,
	// 无条件 SetMode 会把用户显式指定的模式踩掉。
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	web.Register(r, db, bm)

	if web.PprofEnabled() {
		web.RegisterPprof(r)
		log.Printf("pprof 已启用: %s/debug/pprof/ (务必仅绑定内网)", addr)
	}

	srv := &http.Server{Addr: addr, Handler: r}
	go func() {
		log.Printf("xdp-ban listening on %s (db=%s, xdp iface=%s)", addr, dbPath, iface)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Printf("收到停止信号,开始优雅关闭")

	cancelExec()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP 服务关闭异常: %v", err)
	}

	closeXDP()
	log.Printf("已退出")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadPrefixDB() {
	candidates := []string{}
	if p := os.Getenv("XDPBAN_PREFIX_DB"); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, prefixdb.ActivePath())

	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		pdb, err := prefixdb.Load(p)
		if err != nil {
			log.Printf("加载前缀库 %s 失败: %v", p, err)
			continue
		}
		prefixdb.SetGlobal(pdb)
		st := pdb.Stats()
		log.Printf("前缀库已加载(%s): %d 条区间, %d 个国家, %d 个 AS",
			p, st.Entries, st.Countries, st.ASNs)

		if err := prefixdb.Reload(); err != nil && p == prefixdb.ActivePath() {
			log.Printf("应用本地覆盖规则: %v", err)
		}
		return
	}
	log.Printf("未找到 IP 前缀库,按国家/AS 封禁功能不可用 —— 可在界面「IP 库管理」中同步或上传")
}

func seed(db *gorm.DB) {
	var n int64
	db.Model(&model.User{}).Count(&n)
	if n > 0 {
		return
	}
	// 只播一个 admin,也只有一个 admin。曾经这里播四个账号
	// (admin/approver/operator/viewer)配一张角色矩阵,那是为多人分权准备的:
	// 四眼原则要两个可用登录,矩阵按角色关闭页面。四眼和矩阵都已移除 ——
	// 矩阵里 admin 本来就持有全部能力,对唯一的账号从没生效过。
	// 要分权就交给前面的反向代理或独立鉴权层,那一层能同时管住 Web 和邮件审批链接。
	u := &model.User{Username: "admin", Active: true, Email: "admin@example.com"}
	_ = u.SetPassword("admin12345")
	db.Create(u)
	for _, p := range []struct{ t, l string }{
		{"127.0.0.0/8", "环回(硬保护)"},
		{"::1/128", "IPv6 环回"},
		{"8.8.8.8", "公共DNS示例"},
	} {
		db.Create(&model.ProtectedTarget{Target: p.t, Label: p.l, Active: true})
	}
	log.Println("seeded default account admin/admin12345 (change the password!)")
}
