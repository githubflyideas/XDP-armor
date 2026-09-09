package web

import "html/template"

func templates() *template.Template {

	funcs := template.FuncMap{
		"divPPM": func(ppm int) int {
			p := ppm / 10000
			if p > 100 {
				return 100
			}
			return p
		},
		"sub": func(a, b int) int { return a - b },
	}
	t := template.New("").Funcs(funcs)
	template.Must(t.New("_head").Parse(headTpl))
	template.Must(t.New("login.html").Parse(loginTpl))
	template.Must(t.New("dashboard.html").Parse(dashTpl))
	template.Must(t.New("bans.html").Parse(bansTpl))
	template.Must(t.New("lookup.html").Parse(lookupTpl))
	template.Must(t.New("ban_new.html").Parse(banNewTpl))
	template.Must(t.New("ban_detail.html").Parse(banDetailTpl))
	template.Must(t.New("scoped_new.html").Parse(scopedNewTpl))
	template.Must(t.New("scoped_list.html").Parse(scopedListTpl))
	template.Must(t.New("report.html").Parse(reportTpl))
	template.Must(t.New("prefixdb.html").Parse(prefixDBTpl))
	template.Must(t.New("account.html").Parse(accountTpl))
	template.Must(t.New("audit.html").Parse(auditTpl))
	template.Must(t.New("error.html").Parse(errTpl))
	template.Must(t.New("approve.html").Parse(approveTpl))
	template.Must(t.New("approve_done.html").Parse(approveDoneTpl))
	return t
}

const headTpl = `<style>
:root{--ink:#0f1b2d;--steel:#1e3050;--paper:#eef1f5;--accent:#d9411e;--ok:#1f9d55;--warn:#d98a1e;--bad:#cf2f2f;--txt:#1a2433;--muted:#67748a}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;color:var(--txt);background:var(--paper);font-size:15px}
.mono{font-family:"SF Mono",Menlo,Consolas,monospace}
.topbar{height:50px;background:var(--ink);color:#fff;display:flex;align-items:center;padding:0 16px;gap:14px}
.brand{font-weight:700;letter-spacing:.5px;font-size:17px}.brand b{color:var(--accent)}
.spacer{flex:1}.who{font-size:14px;color:#b9c4d6}
.topbar a{color:#b9c4d6;text-decoration:none;font-size:14px}.topbar a:hover{color:#fff}
.shell{display:flex;min-height:calc(100vh - 50px)}
.side{width:210px;background:var(--steel)}.side a{display:block;color:#c3cee0;text-decoration:none;padding:12px 18px;border-left:3px solid transparent;font-size:14px}
.side a:hover{background:#243a5e;color:#fff}.main{flex:1;padding:22px 26px}
h1{font-size:21px;margin:0 0 18px}
.card{background:#fff;border:1px solid #d5dae3;border-radius:4px;margin-bottom:16px}.card .hd{padding:11px 14px;border-bottom:1px solid #e3e7ee;font-weight:600;background:#f7f9fc;font-size:15px}.card .bd{padding:14px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #eceff4;font-size:14px}th{color:var(--muted);text-transform:uppercase;font-size:12px;background:#fafbfd}
.st{display:inline-flex;align-items:center;gap:6px}.st::before{content:"";width:8px;height:8px;border-radius:50%}
.st.ok::before{background:var(--ok)}.st.warn::before{background:var(--warn)}.st.bad::before{background:var(--bad)}.st.mut::before{background:var(--muted)}
.btn{display:inline-block;padding:8px 16px;border-radius:3px;border:1px solid #c3ccd9;background:#fff;color:var(--txt);text-decoration:none;cursor:pointer;font-size:14px}
.btn.primary{background:var(--ink);color:#fff;border-color:var(--ink)}.btn.danger{background:var(--accent);color:#fff;border-color:var(--accent)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.stat{background:#fff;border:1px solid #d5dae3;border-radius:4px;padding:16px}.stat .n{font-size:30px;font-weight:700}.stat .l{color:var(--muted);font-size:13px;margin-top:6px}.stat.bad .n{color:var(--bad)}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 4px;font-weight:600}
input,select{width:100%;padding:9px 10px;border:1px solid #c3ccd9;border-radius:3px;font-size:14px}
.flash{padding:11px 14px;border-radius:4px;margin-bottom:16px}.flash.err{background:#fbe9e7;border:1px solid #f2c2ba;color:#a3271a}
</style>`

const navTpl = `<div class="topbar"><span class="brand">XDP<b>-ban</b></span><span class="spacer"></span>
<span class="who">{{.u.Username}}</span><a href="/logout">退出</a></div>
<div class="shell"><aside class="side">{{range .nav}}<a href="/{{.Key}}">{{.Label}}</a>{{end}}</aside><main class="main">`

const loginTpl = `<!doctype html><html><head><meta charset="utf-8"><title>xdp-ban</title>{{template "_head"}}</head>
<body><div style="max-width:360px;margin:9vh auto">
<div style="text-align:center;margin-bottom:24px"><div style="font-size:26px;font-weight:700;color:#0f1b2d">XDP<span style="color:#d9411e">-ban</span></div>
<div style="color:#67748a;font-size:12px;margin-top:4px">See it. Ban it.</div></div>
<div class="card"><div class="hd">登录 / Sign in</div><div class="bd">
{{if .err}}<div class="flash err">{{.err}}</div>{{end}}
<form method="post" action="/login"><label>用户名</label><input name="username" autofocus>
<label>密码</label><input type="password" name="password">
<div style="margin-top:18px"><button class="btn primary" style="width:100%">登录</button></div></form>
</div></div></div></body></html>`

const dashTpl = `<!doctype html><html><head><meta charset="utf-8"><title>Dashboard · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>Dashboard</h1>
<div class="stats"><div class="stat"><div class="n">{{.pending}}</div><div class="l">待审批</div></div>
<div class="stat"><div class="n">{{.active}}</div><div class="l">生效中封禁</div></div>
<div class="stat {{if .failed}}bad{{end}}"><div class="n">{{.failed}}</div><div class="l">下发失败</div></div>
<div class="stat {{if .driftCount}}bad{{end}}"><div class="n">{{.driftCount}}</div><div class="l">近24h漂移告警</div></div></div>
<div class="card" style="margin-top:16px"><div class="hd">快速操作</div><div class="bd">
<a class="btn primary" href="/bans/new">新建封禁请求</a> <a class="btn" href="/bans">查看全部请求</a>
</div></div></main></div></body></html>`

const bansTpl = `<!doctype html><html><head><meta charset="utf-8"><title>封禁请求 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>封禁请求</h1>
<p><a class="btn primary" href="/bans/new">新建封禁请求</a></p>
<div class="card"><table><thead><tr><th>目标</th><th>动作</th><th>来源</th><th>状态</th><th>时间</th><th></th></tr></thead><tbody>
{{range .reqs}}<tr><td class="mono">{{.Target}}</td><td>{{.ActionType}}</td><td>{{.Source}}</td>
<td><span class="st {{if eq .State "active"}}ok{{else if eq .State "pending"}}warn{{else}}mut{{end}}">{{.State}}</span></td>
<td>{{.CreatedAt.Format "01-02 15:04"}}</td>
<td>{{if eq .State "pending"}}
<form method="post" action="/bans/{{.ID}}/approve" style="display:inline"><input type="hidden" name="csrf_token" value="{{$.csrf}}"><button class="btn primary">批准</button></form>
<form method="post" action="/bans/{{.ID}}/reject" style="display:inline"><input type="hidden" name="csrf_token" value="{{$.csrf}}"><button class="btn danger">驳回</button></form>{{end}}</td></tr>
{{end}}</tbody></table></div></main></div></body></html>`

const banNewTpl = `<!doctype html><html><head><meta charset="utf-8"><title>新建 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>新建封禁请求</h1>
<div class="card" style="max-width:460px"><div class="bd">
{{if .err}}<div class="flash err">{{.err}}</div>{{end}}
{{if .target}}<div class="flash" style="background:#eef4ff;border:1px solid #c3d4f0;color:#1e3050">已根据采样流量预填,请核对后提交审批。</div>{{end}}
<form method="post" action="/bans"><input type="hidden" name="csrf_token" value="{{.csrf}}"><label>目标 IP / CIDR</label><input name="target" value="{{.target}}" placeholder="203.0.113.7 或 203.0.113.0/24" required>
<label>原因</label><input name="reason" value="{{.reason}}" placeholder="ssh 爆破 / 恶意扫描" required>
{{if .selfWarn}}<div style="margin-top:14px;padding:10px 12px;border:1px solid #f2c2ba;border-radius:4px;background:#fbe9e7">
<label style="display:flex;align-items:center;gap:8px;font-weight:600;color:#a3271a;margin:0">
  <input type="checkbox" name="self_ack" value="1" style="width:auto" {{if .selfAck}}checked{{end}} required>
  我已确认会切断自己的访问,继续提交
</label>
<div style="color:#7a3c30;font-size:11.5px;margin-top:6px;line-height:1.5">此确认会记入审计。失联后请在物理控制台上用 <span class="mono">xdp-ban status</span> / <span class="mono">xdp-ban why &lt;ip&gt;</span> 定位 —— 这些规则不会出现在 iptables/nft/firewalld 里。</div>
</div>{{end}}
<div style="margin-top:18px"><button class="btn primary">提交请求</button> <a class="btn" href="/bans">取消</a></div></form>
</div></div></main></div></body></html>`

const banDetailTpl = `<!doctype html><html><head><meta charset="utf-8"><title>详情 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>封禁请求详情</h1>
<div class="card"><div class="bd"><table style="width:auto">
<tr><td style="font-weight:600;width:120px">目标:</td><td class="mono">{{.req.Target}}</td></tr>
<tr><td style="font-weight:600">原因:</td><td>{{.req.Reason}}</td></tr>
<tr><td style="font-weight:600">状态:</td><td><span class="st {{if eq .req.State "active"}}ok{{else if eq .req.State "pending"}}warn{{else}}mut{{end}}">{{.req.State}}</span></td></tr>
<tr><td style="font-weight:600">提交时间:</td><td>{{.req.CreatedAt.Format "2006-01-02 15:04:05"}}</td></tr>
{{if .req.ApprovedByID}}<tr><td style="font-weight:600">批准者:</td><td>{{.approver.Username}}</td></tr>
<tr><td style="font-weight:600">批准时间:</td><td>{{.req.UpdatedAt.Format "2006-01-02 15:04:05"}}</td></tr>{{end}}
</table></div></div>
{{if .canApprove}}<div class="card"><div class="bd">
<form method="post" action="/bans/{{.req.ID}}/approve" style="display:inline"><input type="hidden" name="csrf_token" value="{{.csrf}}"><button class="btn primary">批准</button></form>
<form method="post" action="/bans/{{.req.ID}}/reject" style="display:inline"><input type="hidden" name="csrf_token" value="{{.csrf}}"><button class="btn danger">驳回</button></form>
</div></div>{{end}}
</main></div></body></html>`

const auditTpl = `<!doctype html><html><head><meta charset="utf-8"><title>审计 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>审计日志</h1>
<div class="card"><table><thead><tr><th>时间</th><th>用户</th><th>实体</th><th>事件</th></tr></thead><tbody>
{{range .logs}}<tr><td>{{.OccurredAt.Format "01-02 15:04:05"}}</td><td>{{.ActorLabel}}</td>
<td>{{.EntityType}}#{{.EntityID}}</td><td>{{.Event}}</td></tr>
{{end}}</tbody></table></div>
</main></div></body></html>`

const errTpl = `<!doctype html><html><head><meta charset="utf-8"><title>xdp-ban</title>{{template "_head"}}</head>
<body><div style="max-width:440px;margin:9vh auto"><div class="card"><div class="hd">提示</div><div class="bd">{{.msg}}<p><a class="btn" href="/dashboard">返回</a></p></div></div></div></body></html>`

const approveTpl = `<!doctype html><html><head><meta charset="utf-8"><title>审批 · xdp-ban</title>{{template "_head"}}</head>
<body><div style="max-width:460px;margin:8vh auto"><div class="card"><div class="hd">邮件审批确认</div><div class="bd">
<p><strong>请求目标:</strong> <span class="mono">{{.req.Target}}</span></p>
<p><strong>原因:</strong> {{.req.Reason}}</p>
<p style="color:#98a2b3;font-size:12px;margin-top:16px">点击下方按钮确认审批此请求。链接一次性有效。</p>
<div style="display:flex;gap:10px;margin-top:18px">
<form method="post" action="/approve/{{.token.Token}}" style="flex:1"><input type="hidden" name="action" value="approve">
<button class="btn primary" style="width:100%">批准请求</button></form>
<form method="post" action="/approve/{{.token.Token}}" style="flex:1"><input type="hidden" name="action" value="reject">
<button class="btn danger" style="width:100%">驳回请求</button></form>
</div></div></div></div></body></html>`

const approveDoneTpl = `<!doctype html><html><head><meta charset="utf-8"><title>已完成</title>{{template "_head"}}</head>
<body><div style="max-width:440px;margin:8vh auto"><div class="card"><div class="hd">✓ {{if eq .action "approve"}}已批准{{else}}已驳回{{end}}</div><div class="bd">
<p>{{if eq .action "approve"}}封禁请求已批准并下发执行。{{else}}封禁请求已驳回。{{end}}</p>
<p style="color:#98a2b3;font-size:12px;margin-top:14px">此链接已失效,不能再次使用。</p></div></div></div></body></html>`

const lookupTpl = `<!doctype html><html><head><meta charset="utf-8"><title>IP 查询 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>IP 查询</h1>
<div class="card"><div class="bd">
{{if .err}}<div class="flash err">{{.err}}</div>{{end}}
<form method="post" action="/lookup"><input type="hidden" name="csrf_token" value="{{.csrf}}"><label>源 IP</label>
<input name="ip" value="{{.query}}" placeholder="203.0.113.7" autofocus required>
<div style="margin-top:14px"><button class="btn primary">查询</button></div></form>
</div></div>
{{if .searched}}<div class="card"><div class="hd">查询结果</div><div class="bd">
{{if not .hits}}<p style="color:#67748a">未发现覆盖 {{.query}} 的封禁规则。</p>{{else}}
<table><thead><tr><th>类型</th><th>目标/范围</th><th>状态</th><th>已生效</th><th>原因</th><th>请求人</th><th>批准人</th><th>过期时间</th><th></th></tr></thead><tbody>
{{range .hits}}<tr>
<td>{{if eq .Kind "ban"}}全局{{else}}范围{{end}}</td>
<td class="mono">{{.Target}}</td>
<td><span class="st {{if eq .State "active"}}ok{{else if eq .State "pending"}}warn{{else}}mut{{end}}">{{.State}}</span></td>
<td>{{if .Enforced}}<span class="st ok">是</span>{{else}}<span class="st mut">否</span>{{end}}</td>
<td>{{.Reason}}</td>
<td>{{.RequestedBy}}</td>
<td>{{.ApprovedBy}}</td>
<td>{{.ExpiresAt}}</td>
<td>{{if .CanRollback}}<form method="post" action="/lookup/{{.Kind}}/{{.ID}}/rollback" style="display:inline">
<input type="hidden" name="csrf_token" value="{{$.csrf}}"><button class="btn danger">立即解封</button></form>{{end}}</td>
</tr>{{end}}
</tbody></table>
<p style="color:#98a2b3;font-size:12px;margin-top:12px">若服务在此规则生效后重启过,底层规则可能已经丢失(定向封禁的目标映射不持久化)。</p>
{{end}}
</div></div>{{end}}
</main></div></body></html>`
