package auth

import (
	"github.com/appgate/sdpctl/pkg/factory"
)

type Local struct {
	Factory              *factory.Factory
	Remember, SaveConfig bool
}

func (l Local) Signin() error {
	return nil
}
