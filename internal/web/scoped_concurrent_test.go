package web

import (
	"net/http"
	"sync"
	"testing"

	"github.com/xdpban/xdp-ban/internal/model"
)

func TestScopedBanApprove_ConcurrentApprovalsOnlyOneWins(t *testing.T) {
	db := newScopedTestDB(t)
	requester := mkUser(t, db, "requester", true)
	mkUser(t, db, "approver1", true)
	mkUser(t, db, "approver2", true)

	setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})

	sb := model.ScopedBan{
		Global: true, Country: "XX", PrefixCount: 1, AddressCount: 256,
		State: "pending", RequestedByID: &requester.ID,
	}
	if err := db.Create(&sb).Error; err != nil {
		t.Fatalf("create scoped ban: %v", err)
	}

	r := newScopedRouter(t, db, &fakeRevoker{})
	sid1 := loginAs(t, r, "approver1")
	sid2 := loginAs(t, r, "approver2")

	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		codes[0] = postAs(t, r, sid1, "/scoped/"+itoa(sb.ID)+"/approve", nil).Code
	}()
	go func() {
		defer wg.Done()
		codes[1] = postAs(t, r, sid2, "/scoped/"+itoa(sb.ID)+"/approve", nil).Code
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
