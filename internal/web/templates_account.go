package web

const accountTpl = `<!doctype html><html><head><meta charset="utf-8"><title>账号 · xdp-ban</title>{{template "_head"}}
<style>
.pwform{display:grid;grid-template-columns:1fr;gap:12px;max-width:360px}
.meta{color:#67748a;font-size:13px;line-height:1.7}
.meta code{background:#f1f3f5;padding:1px 5px;border-radius:3px}
</style></head>
<body>` + navTpl + `<h1>账号</h1>

{{if .err}}<div class="flash err">{{.err}}</div>{{end}}
{{if .ok}}<div class="flash" style="background:#e8f5e9;border:1px solid #c8e6c9;color:#2e7d32">{{.ok}}</div>{{end}}

<div class="card"><div class="hd">当前账号</div><div class="bd">
<div class="meta">
用户名 <code>{{.u.Username}}</code>{{if .u.Email}} · 邮箱 <code>{{.u.Email}}</code>{{end}}<br>
{{if .u.LastLoginAt}}上次登录 {{.u.LastLoginAt.Format "2006-01-02 15:04:05"}}{{else}}本次是首次登录{{end}}
</div>
</div></div>

<div class="card"><div class="hd">修改密码</div><div class="bd">
<form method="post" action="/account/password" class="pwform">
<input type="hidden" name="csrf_token" value="{{.csrf}}">
<div><label>当前密码</label><input name="current" type="password" required autocomplete="current-password"></div>
<div><label>新密码(至少 8 位)</label><input name="password" type="password" required minlength="8" autocomplete="new-password"></div>
<div><label>再输一次</label><input name="confirm" type="password" required minlength="8" autocomplete="new-password"></div>
<div><button class="btn primary">修改密码</button></div>
</form>
<div class="meta" style="margin-top:12px">
改密后全部会话立即失效,需要重新登录。<br>
初始口令 <code>admin12345</code> 写在 README 里,是公开的 —— 部署后第一件事就是改掉它。
</div>
</div></div>

<div class="card"><div class="hd">只有一个账号</div><div class="bd">
<div class="meta">
这个工具按一个人自己用来设计:提交和审批可以是同一个人,所以不需要多角色,
也就没有用户管理页。<br>
需要多人分权时,应该由前面的反向代理或独立的鉴权层来做 —— 那一层能同时管住
Web 界面和邮件审批链接,比在这里塞一张角色矩阵更实在。
</div>
</div></div>
</main></div></body></html>`
