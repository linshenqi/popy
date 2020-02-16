package totp

import (
	"errors"
	"github.com/linshenqi/sptty"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"time"
)

const (
	ServiceName = "totp"
)

type Service struct {
	cfg Config
}

func (s *Service) Init(app sptty.Sptty) error {
	if err := app.GetConfig(ServiceName, &s.cfg); err != nil {
		return err
	}

	app.AddRoute("PUT", "/totp-generate", s.putGenerate)
	app.AddRoute("PUT", "/totp-Validate", s.putValidate)

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

func (s *Service) Gererate(endpoint string) (string, string, error) {
	ep, exist := s.cfg.Endpoints[endpoint]
	if !exist {
		return "", "", errors.New("Endpoint Not Found ")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      ep.Issuer,
		AccountName: ep.Issuer,
		Period:      9999,
	})

	if err != nil {
		return "", "", err
	}

	code, err := totp.GenerateCodeCustom(key.Secret(), time.Now(), totp.ValidateOpts{
		Period: uint(ep.Expiry.Seconds()),
		Digits: otp.Digits(ep.CodeLen),
	})

	if err != nil {
		return "", "", err
	}

	return code, key.Secret(), nil
}

func (s *Service) Validate(endpoint string, code string, key string) (bool, error) {
	ep, exist := s.cfg.Endpoints[endpoint]
	if !exist {
		return false, errors.New("Endpoint Not Found ")
	}

	return totp.ValidateCustom(code, key, time.Now(), totp.ValidateOpts{
		Period: uint(ep.Expiry.Seconds()),
		Digits: otp.Digits(ep.CodeLen),
	})
}
