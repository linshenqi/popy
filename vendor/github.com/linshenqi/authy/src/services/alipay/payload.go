package alipay

import (
	"github.com/linshenqi/authy/src/services/oauth"
	v3 "github.com/smartwalle/alipay/v3"
)

type UserInfoResponse struct {
	v3.UserInfoShareRsp
}

func (s *UserInfoResponse) toAuthResponseData() *oauth.Response {
	gender := 0
	if s.Content.Gender == "M" {
		gender = 1
	} else if s.Content.Gender == "F" {
		gender = 2
	}

	return &oauth.Response{
		UnionID:  s.Content.UserId,
		Name:     s.Content.NickName,
		Gender:   gender,
		Province: s.Content.Province,
		City:     s.Content.City,
		Avatar:   s.Content.Avatar,
	}
}
