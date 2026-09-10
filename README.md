<div align="center">

# XDP-ban

**看得见,才封得下。**

一个二进制。封禁落在内核最早的地方。

</div>

---

刀要快,更要有人按住你的手。XDP-ban 就是那只手。

你提交一次封禁,它不立刻动手 —— 停一下,让你再看一眼,点头了,才在 **XDP** 层落下,
在网卡入口,比 netfilter 更早。累犯者刑期递增,直到永不释放。

纯 Go,`CGO_ENABLED=0`,一个静态二进制,eBPF 已在里面。拷过去就能跑。

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
</div>

## 它做什么

- **先停一下** — 两步批准,不可改的审计,一次性邮件链接。为一个人写:一个账号,自己提、自己批。
- **越封越久** — 累犯刑期递增,直到永久。
- **只封该封的** — 按 **国家 / ASN** 圈源,只护一台主机。下手前先算影响面,超配额不放行。
- **纯 XDP** — 不碰 iptables/nftables,直接写 eBPF map,走通用(SKB)模式,任何网卡都认。
- **答得出"网怎么断的"** — 规则天生不进 `iptables`/`nft`/`firewalld`,所以备了 `xdp-ban status` 和 `xdp-ban why <ip>` 直接读内核 map;你要封的源盖住了自己此刻的地址?第一次提交它会拦下你。

## 上路

```bash
# x86_64;arm64 把 amd64 换成 arm64
curl -L -o xdp-ban https://github.com/githubflyideas/XDP-armor/releases/latest/download/xdp-ban-linux-amd64
chmod +x xdp-ban
sudo ./xdp-ban -iface eth0    # http://localhost:8080 —— 挂 XDP 要 root
```

首次运行种下一个账号,**立刻改密码**(它印在这份公开 README 里):

| 用户名 | 密码 |
|---|---|
| `admin` | `admin12345` |

只有一个账号,没有用户管理。提交与批准本是同一人,那步 `pending → approve`
给的是一次反悔的机会,不是逼你找第二双眼睛。要给多人分权,把反代或独立鉴权挡在前面。

数据只在一个 `xdpban.db` 文件里。备份 = 拷这个文件。

全部发布:https://github.com/githubflyideas/XDP-armor/releases

## 按国家 / ASN 封

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
XDPBAN_PREFIX_DB=./ip2asn-v4.tsv.gz ./xdp-ban
```

不给也行,别的照跑,界面会告诉你这功能没开。

## 排障:这些在 `iptables` 里一个都看不到

XDP 挂在驱动钩子上,**在 netfilter 之前**。`iptables -L`、`nft list ruleset`、
`firewall-cmd --list-all` 永远列不出一条封禁,丢再多包也一样。一台刚封掉自己
`/24` 的主机,看着就像一场无因的断网。

同一个二进制答你 —— 不要 `-iface`,不要守护进程活着,什么都不写:

```bash
sudo xdp-ban status            # 内核此刻在拦什么
sudo xdp-ban why 203.0.113.7   # 这地址现在被丢没,哪条规则干的
```

`status` 把每条 map 记录**分成活的和过期的两列**:XDP 从不删键,只拿 `expires_at`
比 `bpf_ktime_get_ns()`,过期就放行 —— 所以"键在 map 里"不等于"这地址在被丢",
一条生的 `bpftool map dump` 会把你引向反面。`why` 拿 `/32` 去问 LPM trie,
答得出真正管事的那条覆盖 `/24`。两者都读 `/sys/fs/bpf/xdp-ban/` 下 pin 住的 map,
那才是真相 —— 不是 SQLite,那里只记你"想"封什么。

**它不让你误砍自己**:提交的源范围盖住你此刻的地址,第一次拦下,提示点名命中前缀
和控制台撤销命令,表单回来带一个"仍要提交"的复选框。存心自封可以,手滑不行。
勾框连同来源地址记进审计 —— 界面变黑后唯一还活着的证据。硬保护集
(`127.0.0.0/8`、`::1/128`、`0.0.0.0/32`,加你配的保护目标)在这之前查,复选框顶不掉它。

## 配置

不带子命令就起守护进程(网页 + 执行器)。子命令只读,不要 root(除读 map):
`xdp-ban status`、`xdp-ban why <ip>`、`xdp-ban version`。

| 参数 / 变量 | 默认 | 干什么 |
|---|---|---|
| `-iface` | —(必填) | 挂 XDP 的生产网卡。缺了就等于封禁只进审计、从不拦包。 |
| `-poll-interval` | `5s` | 多久扫一次新批准的下发 |
| `XDPBAN_DB` | `xdpban.db` | SQLite 文件路径 |
| `XDPBAN_ADDR` | `:8080` | 监听地址 |
| `XDPBAN_BASE_URL` | `http://localhost:8080` | 邮件批准链接前缀 |
| `XDPBAN_IFACE` | — | `-iface` 的替代 |
| `XDPBAN_PREFIX_DB` | — | `ip2asn-v4.tsv[.gz]` 路径;开启按国家/AS 封 |
| `XDPBAN_COOKIE_SECURE` | — | 在 TLS 后设任意值 |
| `XDPBAN_PPROF` | — | 设任意值暴露 `/debug/pprof`(只绑私网口) |
| `GIN_MODE` | `release` | `debug` 找回启动路由清单,平时吵 |

## 用 systemd 部署

```bash
sudo cp xdp-ban /usr/local/bin/xdp-ban
sudo cp deploy/xdp-ban.service /etc/systemd/system/xdp-ban.service
sudo mkdir -p /var/lib/xdp-ban /etc/xdp-ban
echo 'XDPBAN_IFACE=eth0' | sudo tee /etc/xdp-ban/xdp-ban.env
sudo systemctl daemon-reload && sudo systemctl enable --now xdp-ban
```

map pin 在 `/sys/fs/bpf/xdp-ban/`,重启不掉封禁,进程躺着时 `status` 照样能用
(需 bpffs 挂着;没有则打警告降级继续)。宿主重启清空 bpffs,5 分钟对账循环报告漂移。
unit 故意不加 `ProtectSystem=strict` —— 它让 `/sys` 只读,pin 直接失败,
失败的样子是"服务起得来、`status` 却什么都看不到"。

## 从源码构建

只在动它时才需要;发布的二进制已打包 eBPF。要 `clang` 和 `libbpf-dev`。

```bash
make bpf      # clang → cmd/xdpban/obj/xdp_filter.o(go:embed 嵌入)
make build    # xdp-ban;.o 缺了就拒绝跑
make release  # bpf + check + 交叉编译 linux/{amd64,arm64}
```

## License

Apache-2.0。见 [LICENSE](LICENSE)。
