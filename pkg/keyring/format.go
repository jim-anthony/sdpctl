package keyring

import (
	"fmt"

	"github.com/99designs/keyring"
	"github.com/appgate/appgatectl/pkg/hashcode"
)

const (
	keyringService = "appgatectl"
	password       = "password"
	username       = "username"
	bearer         = "bearer"
)

func format(prefix, value string) string {
	return fmt.Sprintf("%d.%s", hashcode.String(prefix), value)
}

func getSecret(key string) (string, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: keyringService,
	})
	if err != nil {
		return "", err
	}
	i, err := ring.Get(key)
	if err != nil {
		return "", err
	}
	return string(i.Data), nil
}

func setSecret(key, value string) error {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: keyringService,
	})
	if err != nil {
		return err
	}
	return ring.Set(keyring.Item{
		Key:  key,
		Data: []byte(value),
	})
}
