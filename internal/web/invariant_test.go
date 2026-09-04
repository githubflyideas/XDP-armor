package web

import (
	"testing"

	"github.com/xdpban/xdp-ban/internal/model"
)

// TestSelfActionAllowedOnMutatingRoutes 钉住的是四眼原则移除之后的不变量:
// 同一个人提交、同一个人审批,必须走得通。这个测试以前钉的是反面(自我操作必须 403),
// 现在反过来 —— 本项目定位是单人自用,提交人和审批人本来就是同一个人,
// 强行要求两个账号只会逼出"建个小号点批准"这种把审计搞脏的用法。
//
// 断言看的是最终状态而不是 HTTP 状态码:scopedBanApprove 在状态改完之后还会展开前缀、
// 校配额、下发 dispatch,这些环节自己就可能返回 403/409,拿状态码当断言会误报。
// 状态在事务里就已经落库,所以"不再是 pending"精确对应"没被自我操作拦住"。
//
// 两步流程(提交 → pending → 批准)本身保留了:它仍然给一次改主意的机会,
// 也让审计日志能分辨"什么时候申请"和"什么时候真正生效"。
func TestSelfActionAllowedOnMutatingRoutes(t *testing.T) {
	cases := []struct {
		name string
		want string
		run  func(t *testing.T) string
	}{
		{
			name: "banApprove lets the requester approve their own request",
			want: "active",
			run: func(t *testing.T) string {
				db := newWebTestDB(t)
				if err := db.AutoMigrate(&model.BanRequest{}, &model.Dispatch{}, &model.ProtectedTarget{}, &model.BanLadder{}); err != nil {
					t.Fatalf("migrate: %v", err)
				}
				db.Exec("DELETE FROM ban_requests")
				u := mkUser(t, db, "self", true)
				req := model.BanRequest{ActionType: "ban", Target: "203.0.113.1", Source: "manual",
					State: "pending", RequestedByID: &u.ID, ApprovalMode: "manual_dual"}
				db.Create(&req)
				r := newWebRouter(t, db)
				sid := loginAs(t, r, "self")
				postAs(t, r, sid, "/bans/"+itoa(req.ID)+"/approve", nil)

				var got model.BanRequest
				if err := db.First(&got, req.ID).Error; err != nil {
					t.Fatalf("reload ban request: %v", err)
				}
				return got.State
			},
		},
		{
			name: "banReject lets the requester reject their own request",
			want: "rejected",
			run: func(t *testing.T) string {
				db := newWebTestDB(t)
				if err := db.AutoMigrate(&model.BanRequest{}, &model.Dispatch{}); err != nil {
					t.Fatalf("migrate: %v", err)
				}
				db.Exec("DELETE FROM ban_requests")
				u := mkUser(t, db, "self", true)
				req := model.BanRequest{ActionType: "ban", Target: "203.0.113.2", Source: "manual",
					State: "pending", RequestedByID: &u.ID, ApprovalMode: "manual_dual"}
				db.Create(&req)
				r := newWebRouter(t, db)
				sid := loginAs(t, r, "self")
				postAs(t, r, sid, "/bans/"+itoa(req.ID)+"/reject", nil)

				var got model.BanRequest
				if err := db.First(&got, req.ID).Error; err != nil {
					t.Fatalf("reload ban request: %v", err)
				}
				return got.State
			},
		},
		{
			name: "scopedBanApprove lets the requester approve their own request",
			want: "active",
			run: func(t *testing.T) string {
				db := newScopedTestDB(t)
				u := mkUser(t, db, "self", true)
				setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})
				sb := model.ScopedBan{Global: true, Country: "XX", PrefixCount: 1, AddressCount: 256,
					State: "pending", RequestedByID: &u.ID}
				db.Create(&sb)
				r := newScopedRouter(t, db, &fakeRevoker{})
				sid := loginAs(t, r, "self")
				postAs(t, r, sid, "/scoped/"+itoa(sb.ID)+"/approve", nil)

				var got model.ScopedBan
				if err := db.First(&got, sb.ID).Error; err != nil {
					t.Fatalf("reload scoped ban: %v", err)
				}
				return got.State
			},
		},
		{
			name: "scopedBanReject lets the requester reject their own request",
			want: "rejected",
			run: func(t *testing.T) string {
				db := newScopedTestDB(t)
				u := mkUser(t, db, "self", true)
				setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})
				sb := model.ScopedBan{Global: true, Country: "XX", PrefixCount: 1, AddressCount: 256,
					State: "pending", RequestedByID: &u.ID}
				db.Create(&sb)
				r := newScopedRouter(t, db, &fakeRevoker{})
				sid := loginAs(t, r, "self")
				postAs(t, r, sid, "/scoped/"+itoa(sb.ID)+"/reject", nil)

				var got model.ScopedBan
				if err := db.First(&got, sb.ID).Error; err != nil {
					t.Fatalf("reload scoped ban: %v", err)
				}
				return got.State
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.run(t); got != tc.want {
				t.Errorf("状态 = %q, 期望 %q(自我审批不应再被拦)", got, tc.want)
			}
		})
	}
}
