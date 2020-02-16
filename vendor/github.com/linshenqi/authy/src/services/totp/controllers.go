package totp

import (
	"encoding/json"
	"github.com/kataras/iris"
	"github.com/linshenqi/sptty"
)

func (s *Service) putGenerate(ctx iris.Context) {
	req := RequestEndpoint{}
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	code, key, err := s.Gererate(req.Endpoint)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	body, _ := json.Marshal(GenerateBody{
		Code: code,
		Key:  key,
	})

	_, _ = ctx.Write(body)
	ctx.StatusCode(iris.StatusOK)
}

func (s *Service) putValidate(ctx iris.Context) {
	req := ValidateRequest{}
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	success, err := s.Validate(req.Endpoint, req.Code, req.Key)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		_, _ = ctx.Write(sptty.NewRequestError(RequestFailed, err.Error()))
		return
	}

	if !success {
		ctx.StatusCode(iris.StatusConflict)
		return
	}

	ctx.StatusCode(iris.StatusOK)
}
