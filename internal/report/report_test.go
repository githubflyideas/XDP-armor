package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:reporttest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.BanRequest{},
		&model.ScopedBan{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, tbl := range []string{"users", "ban_requests", "scoped_bans", "audit_logs"} {
		db.Exec("DELETE FROM " + tbl)
	}
	return db
}

func seedReportData(t *testing.T, db *gorm.DB) (from, to time.Time) {
	t.Helper()

	req := &model.User{Username: "alice", Active: true}
	apr := &model.User{Username: "bob", Active: true}
	db.Create(req)
	db.Create(apr)

	now := time.Now()
	eff := now
	exp := now.Add(time.Hour)
	ttl := int64(3600)

	db.Create(&model.BanRequest{
		Target: "203.0.113.9", Reason: "SSH 爆破", State: "active",
		RequestedByID: &req.ID, ApprovedByID: &apr.ID,
		ApprovedByPolicy: "email_link",
		TTLSeconds:       &ttl, EffectiveAt: &eff, ExpiresAt: &exp,
	})
	db.Create(&model.ScopedBan{
		TargetIP: "10.0.1.100", Country: "CN", ASN: 4134,
		Reason: "AS 洪水", State: "active", PrefixCount: 1520,
		RequestedByID: &req.ID, ApprovedByID: &apr.ID,
		OverrideAck: true,
		TTLSeconds:  &ttl, EffectiveAt: &eff, ExpiresAt: &exp,
	})

	db.Create(&model.BanRequest{
		Target: "127.0.0.1", Reason: "误操作", State: "safety_blocked",
		RequestedByID: &req.ID,
	})

	return now.Add(-time.Hour), now.Add(time.Hour)
}

func TestBuild_CoversBothBanKinds(t *testing.T) {
	db := newTestDB(t)
	from, to := seedReportData(t, db)

	sum, rows, err := Build(db, Filter{From: from, To: to}, "tester")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(rows) != 3 {
		t.Fatalf("行数 = %d, 期望 3(2 条封禁 + 1 条被否决)", len(rows))
	}

	var hasBan, hasScoped bool
	for _, r := range rows {
		switch r.Kind {
		case "ban":
			hasBan = true
		case "scoped_ban":
			hasScoped = true
			if r.Scope != "CN + AS4134" {
				t.Errorf("范围标签 = %q, 期望 \"CN + AS4134\"", r.Scope)
			}
			if !r.OverrideAck {
				t.Error("大范围确认标记丢失")
			}
		}
	}
	if !hasBan || !hasScoped {
		t.Error("报告必须同时包含单点封禁与范围封禁")
	}

	if sum.SafetyBlocked != 1 {
		t.Errorf("保护集否决数 = %d, 期望 1", sum.SafetyBlocked)
	}
	if sum.OverrideCount != 1 {
		t.Errorf("大范围确认数 = %d, 期望 1", sum.OverrideCount)
	}
	if sum.DistinctApprovers != 1 {
		t.Errorf("审批人数 = %d, 期望 1", sum.DistinctApprovers)
	}
}

func TestWriteCSV_SelfDescribing(t *testing.T) {
	db := newTestDB(t)
	from, to := seedReportData(t, db)
	sum, rows, err := Build(db, Filter{From: from, To: to}, "auditor01")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, sum, rows); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()

	if !strings.HasPrefix(out, "\xEF\xBB\xBF") {
		t.Error("CSV 缺少 UTF-8 BOM,Excel 打开会乱码")
	}

	for _, must := range []string{
		"auditor01",
		"统计区间",
		"203.0.113.9",
		"alice",
		"bob",
		"CN + AS4134",
		"邮件链接",
		"保护集否决",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("CSV 缺少必要内容: %q", must)
		}
	}
}

func TestWriteHTML_IncludesControlEvidence(t *testing.T) {
	db := newTestDB(t)
	from, to := seedReportData(t, db)
	sum, rows, err := Build(db, Filter{From: from, To: to}, "auditor01")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, sum, rows); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	for _, must := range []string{
		"两步生效", "保护集否决", "大范围二次确认", "审计留痕",
		"否决 1 次", "确认 1 次",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("HTML 报告缺少控制措施证据: %q", must)
		}
	}

	if !strings.Contains(out, "@page") || !strings.Contains(out, "@media print") {
		t.Error("HTML 报告缺少打印样式")
	}

	if !strings.Contains(out, "table-header-group") {
		t.Error("表头未设置跨页重复")
	}
}

func TestFormatTTL(t *testing.T) {
	cases := []struct {
		secs *int64
		want string
	}{
		{nil, "永久"},
		{ptr(0), "永久"},
		{ptr(600), "10 分钟"},
		{ptr(3600), "1 小时"},
		{ptr(86400), "1 天"},
		{ptr(604800), "7 天"},
	}
	for _, tc := range cases {
		if got := formatTTL(tc.secs); got != tc.want {
			t.Errorf("formatTTL(%v) = %q, 期望 %q", tc.secs, got, tc.want)
		}
	}
}

func TestBuild_RespectsTimeRange(t *testing.T) {
	db := newTestDB(t)
	u := &model.User{Username: "alice", Active: true}
	db.Create(u)

	old := time.Now().Add(-90 * 24 * time.Hour)
	r := &model.BanRequest{Target: "1.2.3.4", State: "active", RequestedByID: &u.ID}
	db.Create(r)
	db.Model(r).Update("created_at", old)

	now := time.Now()
	_, rows, err := Build(db, Filter{From: now.Add(-time.Hour), To: now}, "t")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("区间外记录不应出现在报告中,实际 %d 行", len(rows))
	}
}

func ptr(v int64) *int64 { return &v }
