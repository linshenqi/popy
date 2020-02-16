package oss

type Config struct {
	Endpoints map[string]Endpoint `yaml:"endpoints"`
}

type Endpoint struct {
	Provider  string `yaml:"provider"`
	AppKey    string `yaml:"app_key"`
	AppSecret string `yaml:"app_secret"`
	Bucket    string `yaml:"bucket"`
	Zone      string `yaml:"zone"`
}

func (s *Config) ConfigName() string {
	return ServiceName
}

func (s *Config) Validate() error {
	return nil
}

func (s *Config) Default() interface{} {
	return &Config{}
}
