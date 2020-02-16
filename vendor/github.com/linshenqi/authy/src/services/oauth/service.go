package oauth

import (
	"errors"
	"github.com/linshenqi/sptty"
)

const (
	ServiceName = "oauth"
)

type Service struct {
	cfg            Config
	oauthProviders map[string]IOAuthProvider
}

func (s *Service) Init(app sptty.Sptty) error {
	if err := app.GetConfig(ServiceName, &s.cfg); err != nil {
		return err
	}

	app.AddRoute("POST", "/oauth", s.postAuth)
	app.AddRoute("GET", "/oauth-endpoint", s.getEndpoint)

	s.initProviders()

	return nil
}

func (s *Service) initProviders() {
	for k, v := range s.cfg.Endpoints {
		provider, err := s.getProvider(v.Provider)
		if err != nil {
			continue
		}

		provider.AddEndpoint(k, v)
	}

	for _, provider := range s.oauthProviders {
		provider.Init()
	}
}

func (s *Service) Release() {

}

func (s *Service) Enable() bool {
	return true
}

func (s *Service) ServiceName() string {
	return ServiceName
}

func (s *Service) OAuth(req Request) (Response, error) {
	resp := Response{
		Type: req.Provider,
	}

	provider, err := s.getProvider(req.Provider)
	if err != nil {
		return resp, err
	}

	respData, err := provider.OAuth(&req)
	if err != nil {
		return resp, err
	}

	respData.Type = req.Provider
	return resp, nil
}

func (s *Service) getProvider(oauthType string) (IOAuthProvider, error) {
	provider, exist := s.oauthProviders[oauthType]
	if !exist {
		return nil, errors.New("Provider Not Found ")
	}

	return provider, nil
}

func (s *Service) findEndpoint(oauthType string, endpoint string) (*Endpoint, error) {
	provider, err := s.getProvider(oauthType)
	if err != nil {
		return nil, err
	}

	return provider.GetEndpoint(endpoint)
}

func (s *Service) SetupProviders(providers map[string]IOAuthProvider) {
	s.oauthProviders = providers
}
