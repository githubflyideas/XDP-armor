package web

// navSection 是左侧导航的一项。
//
// 这里曾经是 internal/policy 的 NavSections(role):一张 role → capability 矩阵,
// 每个页面挂一个 requireCap 闸门,导航按能力过滤。整个机制服务的是"多人分权",
// 而这个工具是一个人自己用的 —— 唯一的账号是 admin,矩阵里 admin 本来就持有全部能力,
// 于是那套东西从来没有真正拒绝过任何人,只是让每条路由多绕一层。
//
// 现在导航就是一个静态列表,权限判断只剩一条:登录了没有(requireLogin)。
// 真要分权,应该由前面的反向代理或者一个独立的鉴权层来做,不该塞在这里。
type navSection struct {
	Key   string
	Label string
}

var navSections = []navSection{
	{"dashboard", "Dashboard"},
	{"bans", "封禁请求"},
	{"lookup", "IP 查询"},
	{"scoped", "范围封禁"},
	{"prefixdb", "IP 库管理"},
	{"audit", "审计日志"},
	{"report", "合规报告"},
	{"account", "账号"},
}
