package jwt

import (
	"time"
)

type Config struct {
	Expiry time.Duration `yaml:"expiry"`
}

func (s *Config) ConfigName() string {
	return ServiceName
}

func (s *Config) Validate() error {
	return nil
}

func (s *Config) Default() interface{} {
	return &Config{
		Expiry: 24 * time.Hour,
	}
}
