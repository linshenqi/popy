package oauth

import (
	"encoding/json"
	"github.com/kataras/iris"
	"github.com/linshenqi/sptty"
)

func (s *Service) postAuth(ctx iris.Context) {
	req := Request{}
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(ErrAuthFailed, err.Error()))
		return
	}

	resp, err := s.OAuth(req)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(ErrAuthFailed, err.Error()))
		return
	}

	ctx.StatusCode(iris.StatusOK)
	body, _ := json.Marshal(resp)
	_, _ = ctx.Write(body)
}

func (s *Service) getEndpoint(ctx iris.Context) {
	endpoint := ctx.URLParam("endpoint")
	oauthType := ctx.URLParam("type")

	ep, err := s.findEndpoint(oauthType, endpoint)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(ErrEndpointNotFound, err.Error()))
		return
	}

	ctx.StatusCode(iris.StatusOK)
	body, _ := json.Marshal(ep)
	_, _ = ctx.Write(body)
}
