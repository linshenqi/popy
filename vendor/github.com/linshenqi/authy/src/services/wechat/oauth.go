package wechat

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/linshenqi/authy/src/services/oauth"
)

type OAuth struct {
	oauth.BaseOAuth
}

func (s *OAuth) OAuth(req *oauth.Request) (*oauth.Response, error) {
	endpoint, err := s.PreAuth(req)
	if err != nil {
		return nil, err
	}

	resp, err := s.doAuth(endpoint.AppID, endpoint.AppSecret, req.Code)
	if err != nil {
		return nil, err
	}

	user, err := s.getUserInfo(resp.AccessToken, resp.OpenID)
	if err != nil {
		return nil, err
	}

	return user.toAuthResponseData(), nil
}

func (s *OAuth) doAuth(appID string, secret string, code string) (OAuthResponse, error) {
	rt := OAuthResponse{}
	url := fmt.Sprintf("https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		appID,
		secret,
		code)

	resp, err := s.Http.R().Get(url)

	if err != nil {
		return rt, err
	} else {
		err = json.Unmarshal(resp.Body(), &rt)
		if err != nil {
			return rt, err
		} else {
			if rt.ErrCode != WxOK {
				return rt, errors.New(fmt.Sprintf("ErrCode: %d, ErrMsg: %s", rt.ErrCode, rt.ErrMsg))
			}

			return rt, nil
		}
	}
}

func (s *OAuth) getUserInfo(accessToken string, openID string) (UserInfoResponse, error) {
	rt := UserInfoResponse{}
	url := fmt.Sprintf("https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s",
		accessToken,
		openID)

	resp, err := s.Http.R().Get(url)

	if err != nil {
		return rt, err
	} else {
		err = json.Unmarshal(resp.Body(), &rt)
		if err != nil {
			return rt, err
		} else {
			if rt.ErrCode != WxOK {
				return rt, errors.New(fmt.Sprintf("ErrCode: %d, ErrMsg: %s", rt.ErrCode, rt.ErrMsg))
			}

			return rt, nil
		}
	}
}
