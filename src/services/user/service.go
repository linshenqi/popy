package user

import (
	"errors"
	"fmt"
	jwt2 "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/linshenqi/authy/src/services/jwt"
	"github.com/linshenqi/authy/src/services/oauth"
	"github.com/linshenqi/collapsar/src/services/oss"
	"github.com/linshenqi/sptty"
)

const (
	ServiceName     = "user"
	AuthHeader      = "Authorization"
	AuthTokenPrefix = "Bearer"
)

type Service struct {
	db    *gorm.DB
	oauth *oauth.Service
	jwt   *jwt.Service
	oss   *oss.Service
}

func (s *Service) Init(app sptty.Sptty) error {
	s.db = app.Model().(*sptty.ModelService).DB()
	s.oauth = app.GetService(oauth.ServiceName).(*oauth.Service)
	s.jwt = app.GetService(jwt.ServiceName).(*jwt.Service)

	app.AddModel(&Credential{})
	app.AddModel(&Role{})
	app.AddModel(&User{})

	// 用户认证(登录)
	app.AddRoute("POST", "/auth", s.postAuth)

	// 创建用户(注册)
	app.AddRoute("POST", "/users", s.postRegister)

	// 获取个人信息
	app.AddRoute("GET", "/users/{id:string}", nil)

	// 修改个人信息
	app.AddRoute("PUT", "/users/{id:string}", nil)

	// 修改密码
	app.AddRoute("PUT", "/users/{id:string}/password", nil)

	// 绑定邮箱
	app.AddRoute("PUT", "/users/{id:string}/email", nil)

	// 绑定手机
	app.AddRoute("PUT", "/users/{id:string}/mobile", nil)

	// 修改头像
	app.AddRoute("PUT", "/users/{id:string}/avatar", nil)

	if err := s.CreateDefaultRole(); err != nil {
		sptty.Log(sptty.ErrorLevel, fmt.Sprintf("Create Default Role Failed: %s", err.Error()), ServiceName)
	}

	return nil
}

func (s *Service) Release() {
}

func (s *Service) Enable() bool {
	return true
}

func (s *Service) ServiceName() string {
	return ServiceName
}

func (s *Service) Auth(req RequestAuth) (*User, error) {
	var u *User
	var err error
	switch req.Provider {
	case AuthNormal:
		// 根据id/密码认证
		u, err = s.doNormalAuth(req)

	case oauth.WeChat, oauth.AliPay:
		// 微信/支付宝oauth认证
		u, err = s.doOAuth(req)

	default:
		return nil, errors.New("Auth Type Not Found ")
	}

	if err != nil {
		return nil, err
	}

	// 生成token
	if err := s.userSign(u); err != nil {
		return nil, err
	}

	return u.Serialize(), nil
}

func (s *Service) userSign(user *User) error {
	token, err := s.jwt.Sign(jwt2.MapClaims{
		"id": user.ID,
	})

	if err != nil {
		return err
	}

	user.Token = token
	return nil
}

func (s *Service) doOAuth(req RequestAuth) (*User, error) {
	req.Endpoint = req.Provider
	resp, err := s.oauth.OAuth(req.Request)
	if err != nil {
		return nil, err
	}

	// oauth认证成功
	u, err := s.AuthUserByOAuth(req.Provider, resp.OpenID, resp.UnionID)
	if err != nil {
		// 根据oauth信息创建用户
		u, err = s.CreateUserByOAuth(resp)
		if err != nil {
			return nil, err
		}
	}

	// TODO: 保存头像

	return u, nil
}

func (s *Service) doNormalAuth(req RequestAuth) (*User, error) {
	return s.AuthUserByID(req.ID, req.Pwd)
}

func (s *Service) UserRegister(req RequestRegister) (*User, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	u, err := s.CreateUserByRegister(req)
	if err != nil {
		return nil, err
	}

	// 生成token
	if err := s.userSign(u); err != nil {
		return nil, err
	}

	return u.Serialize(), nil
}
