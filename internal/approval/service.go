package approval

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
)

const TokenTTL = 10 * time.Minute

type Service struct {
	db       *gorm.DB
	baseURL  string
	mailSend func(to, subj, body string) error
}

func NewService(db *gorm.DB, baseURL string) *Service {
	return &Service{
		db:      db,
		baseURL: baseURL,
		mailSend: func(to, subj, body string) error {

			log.Printf("[MAIL] To:%s\nSubj:%s\nBody:\n%s\n", to, subj, body)
			return nil
		},
	}
}

func (s *Service) GenTokensAndSend(req *model.BanRequest, requesterID *uint) error {
	if req.ApprovalMode != "manual_dual" {
		return nil
	}

	// 收件人就是启用中的账号。曾经这里筛 role IN ('admin','approver') 并排掉提交人
	// 自己 —— 那两条都是四眼原则的配套动作:排掉自己是为了强制第二个人,筛角色是为了
	// 只发给有审批权的人。四眼和角色都已移除,只剩一个 admin,再筛就等于一个审批人都
	// 找不到,邮件路径会静默走进 approval_mail_skipped。
	var approvers []model.User
	if err := s.db.Where("active = ?", true).
		Limit(2).Find(&approvers).Error; err != nil {
		return fmt.Errorf("查找审批人: %w", err)
	}
	if len(approvers) == 0 {

		_ = model.WriteAudit(s.db, requesterID, "system", "BanRequest",
			fmt.Sprint(req.ID), "approval_mail_skipped", "无可用审批人")
		return nil
	}

	approver := approvers[0]

	token := randToken()
	now := time.Now()
	approvalToken := &model.ApprovalToken{
		BanRequestID: req.ID,
		ApproverID:   approver.ID,
		Token:        token,
		ExpiresAt:    now.Add(TokenTTL),
		SentToEmail:  approver.Email,
	}
	if err := s.db.Create(approvalToken).Error; err != nil {
		return fmt.Errorf("创建审批令牌: %w", err)
	}

	requester := "unknown"
	if requesterID != nil {
		requester = fmt.Sprintf("user#%d", *requesterID)
	}

	approveLink := fmt.Sprintf("%s/approve/%s", s.baseURL, token)
	subject := fmt.Sprintf("[xdp-ban] 审批请求:%s", req.Target)
	body := fmt.Sprintf(`您收到一条 xdp-ban 审批请求，请点击下方链接审批（%s 内有效）:

目标: %s
原因: %s
提交者: %s

审批链接:
%s

此链接一次性，用后失效。
`, TokenTTL, req.Target, req.Reason, requester, approveLink)

	if err := s.mailSend(approver.Email, subject, body); err != nil {

		log.Printf("发送审批邮件到 %s 失败: %v", approver.Email, err)
		_ = model.WriteAudit(s.db, requesterID, "mail", "ApprovalToken",
			fmt.Sprint(approvalToken.ID), "mail_failed", err.Error())
		return nil
	}

	_ = model.WriteAudit(s.db, requesterID, "mail", "ApprovalToken",
		fmt.Sprint(approvalToken.ID), "mail_sent", approver.Email)
	return nil
}

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}
