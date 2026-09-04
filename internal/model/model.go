package model

import (
	"fmt"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// User 是登录账号。
//
// 曾经这里还有 Role(角色矩阵)、AuthSource/LDAPDn(为 LDAP 预留)。角色矩阵里
// admin 持有全部能力,而部署形态就是一个 admin,那张矩阵从没拒绝过谁;LDAP 只有
// 字段没有实现。两者都已删掉 —— 旧库里残留的列不影响读写(GORM 不删列,插入
// 时不带这些列,SQLite 用列默认值补上)。
type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;not null"`
	Email        string
	PasswordHash string
	Active       bool `gorm:"not null;default:true"`
	LastLoginAt  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (u *User) SetPassword(pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(h)
	return nil
}
func (u *User) CheckPassword(pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) == nil
}
func (u *User) Label() string { return "user:" + u.Username }

type BanRequest struct {
	ID               uint   `gorm:"primaryKey"`
	ActionType       string `gorm:"not null"`
	Target           string `gorm:"index;not null"`
	Source           string `gorm:"not null;default:manual"`
	ApprovalMode     string `gorm:"not null;default:manual_dual"`
	State            string `gorm:"index;not null;default:pending"`
	RequestedByID    *uint
	ApprovedByID     *uint
	ApprovedByPolicy string
	SecondApproverID *uint
	Reason           string
	TTLSeconds       *int64
	Conditions       string
	EffectiveAt      *time.Time
	ExpiresAt        *time.Time
	ClearedAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Dispatch struct {
	ID           uint   `gorm:"primaryKey"`
	BanRequestID uint   `gorm:"not null"`
	BanID        string `gorm:"index;not null"`
	NodeID       string `gorm:"not null;default:local"`
	Payload      string `gorm:"not null"`
	State        string `gorm:"index;not null;default:pending"`
	LastError    string
	Attempts     int
	AckedAt      *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type AuditLog struct {
	ID         uint `gorm:"primaryKey"`
	UserID     *uint
	ActorLabel string
	EntityType string `gorm:"index;not null"`
	EntityID   string `gorm:"index"`
	Event      string `gorm:"not null"`
	Detail     string
	OccurredAt time.Time `gorm:"not null"`
	CreatedAt  time.Time
}

type ApprovalToken struct {
	ID           uint      `gorm:"primaryKey"`
	BanRequestID uint      `gorm:"not null"`
	ApproverID   uint      `gorm:"not null"`
	Token        string    `gorm:"uniqueIndex;not null"`
	ExpiresAt    time.Time `gorm:"index;not null"`
	UsedAt       *time.Time
	SentToEmail  string
	CreatedAt    time.Time
}

type ProtectedTarget struct {
	ID          uint   `gorm:"primaryKey"`
	Target      string `gorm:"uniqueIndex;not null"`
	Label       string
	Active      bool `gorm:"not null;default:true"`
	CreatedByID *uint
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type BanLadder struct {
	ID           uint   `gorm:"primaryKey"`
	Target       string `gorm:"uniqueIndex;not null"`
	Level        int    `gorm:"not null;default:0"`
	OffenseCount int    `gorm:"not null;default:0"`
	LastBannedAt *time.Time
	ObserveUntil *time.Time
	ExpiresAt    *time.Time
	Permanent    bool `gorm:"not null;default:false"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ScopedBan struct {
	ID uint `gorm:"primaryKey"`

	TargetIP string `gorm:"index;not null"`
	Global   bool   `gorm:"not null;default:false"`

	Country string `gorm:"index"`
	ASN     uint32 `gorm:"index"`

	PrefixCount  int    `gorm:"not null"`
	AddressCount uint64 `gorm:"not null"`
	ResolvedAt   time.Time

	Reason     string
	State      string `gorm:"index;not null;default:pending"`
	TTLSeconds *int64

	RequestedByID *uint
	ApprovedByID  *uint

	OverrideAck bool `gorm:"not null;default:false"`

	EffectiveAt *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (s *ScopedBan) Label() string {
	scope := "任意源"
	switch {
	case s.Country != "" && s.ASN != 0:
		scope = s.Country + "/AS" + itoa64(uint64(s.ASN))
	case s.Country != "":
		scope = s.Country
	case s.ASN != 0:
		scope = "AS" + itoa64(uint64(s.ASN))
	}
	if s.Global {
		return scope + " → 全局(所有受保护目标)"
	}
	return scope + " → " + s.TargetIP
}

func itoa64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func Open(path string) (*gorm.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),

		PrepareStmt: true,

		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := db.AutoMigrate(
		&User{}, &BanRequest{}, &Dispatch{}, &AuditLog{},
		&ApprovalToken{}, &ProtectedTarget{}, &BanLadder{}, &ScopedBan{},
	); err != nil {
		return nil, err
	}

	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil {
		return nil, fmt.Errorf("检查 journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return nil, fmt.Errorf("期望 WAL 模式,实际为 %q(并发读写会互相阻塞)", mode)
	}

	return db, nil
}

func WriteAudit(db *gorm.DB, userID *uint, actor, entityType, entityID, event, detailJSON string) error {
	return db.Create(&AuditLog{
		UserID: userID, ActorLabel: actor, EntityType: entityType,
		EntityID: entityID, Event: event, Detail: detailJSON,
		OccurredAt: time.Now(),
	}).Error
}
