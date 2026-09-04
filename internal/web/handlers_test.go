package web

import (
	"net/http"
	"sync"
	"testing"

	"github.com/xdpban/xdp-ban/internal/model"
)

func TestBanApprove_ConcurrentApprovalsOnlyOneWins(t *testing.T) {
	db := newWebTestDB(t)
	if err := db.AutoMigrate(&model.BanRequest{}, &model.Dispatch{}, &model.ProtectedTarget{}, &model.BanLadder{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM ban_requests")
	db.Exec("DELETE FROM dispatches")
	db.Exec("DELETE FROM protected_targets")
	db.Exec("DELETE FROM ban_ladders")

	requester := mkUser(t, db, "requester", true)
	mkUser(t, db, "approver1", true)
	mkUser(t, db, "approver2", true)

	req := model.BanRequest{
		ActionType: "ban", Target: "203.0.113.7", Source: "manual",
		State: "pending", RequestedByID: &requester.ID, ApprovalMode: "manual_dual",
	}
	if err := db.Create(&req).Error; err != nil {
		t.Fatalf("create ban request: %v", err)
	}

	r := newWebRouter(t, db)
	sid1 := loginAs(t, r, "approver1")
	sid2 := loginAs(t, r, "approver2")

	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		codes[0] = postAs(t, r, sid1, "/bans/"+itoa(req.ID)+"/approve", nil).Code
	}()
	go func() {
		defer wg.Done()
		codes[1] = postAs(t, r, sid2, "/bans/"+itoa(req.ID)+"/approve", nil).Code
	}()
	wg.Wait()

	var wins, conflicts int
	for _, c := range codes {
		switch c {
		case http.StatusFound:
			wins++
		case http.StatusConflict:
			conflicts++
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Errorf("并发批准结果 codes=%v,期望恰好一胜(302)一冲突(409)", codes)
	}

	var n int64
	db.Model(&model.AuditLog{}).Where("event = ?", "approved").Count(&n)
	if n != 1 {
		t.Errorf("approved 审计记录数 = %d, 期望恰好 1 条", n)
	}
}
