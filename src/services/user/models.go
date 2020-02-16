package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/linshenqi/authy/src/services/oauth"
	"github.com/linshenqi/sptty"
	"time"
)

const (
	StatusNormal = "normal"
	DefaultRole  = "User"
)

type OAuthCredential struct {
	OpenID  string `json:"open_id"`
	UniodID string `json:"union_id"`
}

type User struct {
	ID string `gorm:"size:32;primary_key" json:"id"`

	Name     string `gorm:"size:64" json:"name"`
	Pwd      string `gorm:"size:64" json:"-"`
	Gender   int    `json:"gender"`
	Location string `gorm:"size:64" json:"location"`
	Avatar   string `gorm:"size:1024" json:"avatar"`

	// id
	Mobile string `gorm:"size:32;primary_key" json:"mobile"`
	// id
	Idc string `gorm:"size:64;primary_key" json:"idc"`
	// id
	Email string `gorm:"size:256;primary_key" json:"email"`

	Status  string    `gorm:"size:256" json:"status"`
	Created time.Time `json:"-"`

	RoleID string `gorm:"size:32" json:"-"`
	Role   Role   `gorm:"foreignkey:RoleID" json:"role"`

	CredentialID string     `gorm:"size:32" json:"-"`
	Credential   Credential `gorm:"foreignkey:CredentialID" json:"credential"`

	Token string `gorm:"_" json:"token"`
}

func (u *User) Serialize() *User {
	return u
}

func (u *User) FromOAuthResponse(resp oauth.Response) {
	u.Name = resp.Name
	u.Gender = resp.Gender
}

type Role struct {
	ID   string `gorm:"size:32;primary_key" json:"id"`
	Name string `gorm:"size:64" json:"name"`
}

type Credential struct {
	ID                string `gorm:"size:32;primary_key" json:"id"`
	Wechat            string `json:"wechat"`
	WechatMiniprogram string `json:"wechat_miniprogram"`
	Alipay            string `json:"alipay"`
}

func (s *Service) UserExist(id string) error {
	u := User{}
	q := s.db.Where(fmt.Sprintf("idc = '%s' or email = '%s' or mobile = '%s'", id, id, id))
	err := q.Preload("Role").Preload("Credential").First(&u).Error
	return err
}

func (s *Service) AuthUserByID(id string, pwd string) (*User, error) {
	u := User{}
	q := s.db.Where("pwd = ?", sptty.Sha1(pwd)).Where(fmt.Sprintf("idc = '%s' or email = '%s' or mobile = '%s'", id, id, id))
	err := q.Preload("Role").Preload("Credential").First(&u).Error
	return &u, err
}

func (s *Service) AuthUserByOAuth(oauthType string, openID string, unionID string) (*User, error) {
	u := User{}
	q := s.db.Joins("inner join roles on users.role_id = roles.id").Joins("inner join credentials on users.credential_id = credentials.id")
	switch oauthType {
	case oauth.WeChat:
		q = q.Where(fmt.Sprintf("wechat like '%%%s%%' or wechat like '%%%s%%'", openID, unionID))

	case oauth.AliPay:
		q = q.Where(fmt.Sprintf("alipay like '%%%s%%' or wechat like '%%%s%%'", openID, unionID))

	case oauth.WeChatMiniProgram:
		q = q.Where(fmt.Sprintf("wechat_miniprogram like '%%%s%%' or wechat like '%%%s%%'", openID, unionID))

	default:
		return nil, errors.New("oauthType Error")
	}

	err := q.Preload("Role").Preload("Credential").First(&u).Error
	return &u, err
}

func (s *Service) GetRoleByName(name string) (*Role, error) {
	var r Role
	q := s.db.Where("name = ?", name)
	err := q.First(&r).Error
	return &r, err
}

func (s *Service) CreateDefaultRole() error {
	_, err := s.GetRoleByName(DefaultRole)
	if err == nil {
		return nil
	}

	role := Role{
		ID:   sptty.GenerateUID(),
		Name: DefaultRole,
	}

	return s.db.Save(&role).Error
}

func (s *Service) CreateCredential(oauthType string, credential *OAuthCredential) (*Credential, error) {
	c := Credential{
		ID: sptty.GenerateUID(),
	}

	if oauthType != "" {
		body, _ := json.Marshal(credential)
		switch oauthType {
		case oauth.AliPay:
			c.Alipay = string(body)

		case oauth.WeChat:
			c.Wechat = string(body)

		case oauth.WeChatMiniProgram:
			c.WechatMiniprogram = string(body)

		default:
			return nil, errors.New("oauthType Error")
		}
	}

	return &c, s.db.Save(&c).Error
}

func (s *Service) CreateUserByOAuth(oauthResp oauth.Response) (*User, error) {
	// 获取角色
	role, err := s.GetRoleByName(DefaultRole)
	if err != nil {
		return nil, err
	}

	// 创建用户凭证
	userCredential, err := s.CreateCredential(oauthResp.Type, &OAuthCredential{
		OpenID:  oauthResp.OpenID,
		UniodID: oauthResp.UnionID,
	})

	if err != nil {
		return nil, err
	}

	u := User{
		ID:           sptty.GenerateUID(),
		Status:       StatusNormal,
		Created:      time.Now(),
		RoleID:       role.ID,
		CredentialID: userCredential.ID,
	}

	u.FromOAuthResponse(oauthResp)

	if err := s.db.Save(&u).Error; err != nil {
		return nil, err
	}

	return &u, nil
}

func (s *Service) CreateUserByRegister(req RequestRegister) (*User, error) {
	// 检测用户是否已存在
	if err := s.UserExist(req.ID); err == nil {
		return nil, errors.New("User Exist ")
	}

	// 获取角色
	role, err := s.GetRoleByName(DefaultRole)
	if err != nil {
		return nil, err
	}

	// 创建用户凭证
	userCredential, err := s.CreateCredential("", nil)
	if err != nil {
		return nil, err
	}

	u := User{
		ID:           sptty.GenerateUID(),
		Status:       StatusNormal,
		Created:      time.Now(),
		RoleID:       role.ID,
		CredentialID: userCredential.ID,
		Pwd:          req.Pwd,
		Name:         req.ID,
	}

	switch req.Type {
	case RegTypeMobile:
		u.Mobile = req.ID
	case RegTypeEmail:
		u.Email = req.ID
	}

	if err := s.db.Save(&u).Error; err != nil {
		return nil, err
	}

	return &u, nil
}
