package keyring

import (
	"fmt"

	"github.com/99designs/keyring"
	"github.com/AlecAivazis/survey/v2"
	"github.com/appgate/appgatectl/pkg/filesystem"
	"github.com/appgate/appgatectl/pkg/hashcode"
	"github.com/appgate/appgatectl/pkg/prompt"
	"github.com/spf13/viper"
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

var passwordPrompt = func(s string) (string, error) {
	var pwd string
	err := prompt.SurveyAskOne(&survey.Password{Message: s}, &pwd, survey.WithValidator(survey.Required))
	if err != nil {
		return "", err
	}
	return pwd, nil
}

func config() keyring.Config {
	cfg := keyring.Config{
		KeychainPasswordFunc:    passwordPrompt,
		FilePasswordFunc:        passwordPrompt,
		FileDir:                 filesystem.ConfigDir(),
		KWalletAppID:            keyringService,
		PassDir:                 keyringService,
		WinCredPrefix:           keyringService,
		KeychainName:            keyringService,
		ServiceName:             keyringService,
		LibSecretCollectionName: keyringService,
	}
	if v := viper.Get("backend"); v != nil && len(v.(string)) > 0 {
		backend := v.(string)
		cfg.AllowedBackends = append(cfg.AllowedBackends, keyring.BackendType(backend))
	}
	return cfg
}

func getSecret(key string) (string, error) {
	keyring.Debug = true
	ring, err := keyring.Open(config())
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
	keyring.Debug = true
	ring, err := keyring.Open(config())
	if err != nil {
		return err
	}
	return ring.Set(keyring.Item{
		Key:  key,
		Data: []byte(value),
	})
}
