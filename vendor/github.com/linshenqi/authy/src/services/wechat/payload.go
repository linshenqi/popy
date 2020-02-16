package wechat

import "github.com/linshenqi/authy/src/services/oauth"

const (
	WxOK = 0
)

type Response struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type MiniProgramAuthResponse struct {
	Response
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid"`
}

func (s *MiniProgramAuthResponse) toAuthResponseData() *oauth.Response {
	return &oauth.Response{
		OpenID:  s.OpenID,
		UnionID: s.UnionID,
	}
}

type OAuthResponse struct {
	Response
	AccessToken  string `json:"access_token"`
	Expires      int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
}

type UserInfo struct {
	OpenID     string   `json:"openid"`
	UnionID    string   `json:"unionid"`
	NickName   string   `json:"nickname"`
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgUrl string   `json:"headimgurl"`
	Privileges []string `json:"privilege"`
}

type UserInfoResponse struct {
	Response
	UserInfo
}

func (s *UserInfoResponse) toAuthResponseData() *oauth.Response {
	return &oauth.Response{
		OpenID:   s.OpenID,
		UnionID:  s.UnionID,
		Name:     s.NickName,
		Gender:   s.Sex,
		Province: s.Province,
		City:     s.City,
		Country:  s.Country,
		Avatar:   s.HeadImgUrl,
	}
}
