package user

import (
	"errors"
	"github.com/linshenqi/authy/src/services/oauth"
	"regexp"
)

const (
	AuthNormal = "normal"

	RegTypeMobile = "mobile"
	RegTypeEmail  = "email"
)

const (
	ErrAuth     = "ErrAuth"
	ErrRegister = "ErrRegister"
)

type RequestAuth struct {
	oauth.Request

	ID  string `json:"id"`
	Pwd string `json:"pwd"`
}

type RequestRegister struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Pwd   string `json:"pwd"`
	Code  string `json:"code"`
	Token string `json:"token"`
}

func (s *RequestRegister) Validate() error {
	if s.ID == "" {
		return errors.New("ID Is Required ")
	}

	if s.Pwd == "" {
		return errors.New("Password Is Required ")
	}

	if s.Code == "" {
		return errors.New("Code Is Required ")
	}

	if s.Token == "" {
		return errors.New("Token Is Required ")
	}

	switch s.Type {
	case RegTypeMobile:

	case RegTypeEmail:
		if !VerifyEmailFormat(s.ID) {
			return errors.New("Email Format Error ")
		}

	default:
		return errors.New("Type Error ")
	}

	return nil
}

func VerifyEmailFormat(email string) bool {
	pattern := `\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*`
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}
