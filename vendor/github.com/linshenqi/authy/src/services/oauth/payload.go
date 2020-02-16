package oauth

const (
	ErrAuthFailed       = "ErrAuthFailed"
	ErrEndpointNotFound = "EndpointNotFound"
)

const (
	WeChat            = "wechat"
	WeChatMiniProgram = "wechat_miniprogram"
	AliPay            = "alipay"
)

type Request struct {
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Code     string `json:"code"`
}

type Response struct {
	Type string `json:"type"`

	OpenID  string `json:"open_id"`
	UnionID string `json:"union_id"`
	Name    string `json:"name"`

	// 0:未知 1:男 2:女
	Gender int `json:"gender"`

	Province string `json:"province"`
	City     string `json:"city"`
	Country  string `json:"country"`
	Avatar   string `json:"avatar"`
}
