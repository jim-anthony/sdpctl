package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	"github.com/appgate/sdpctl/pkg/configuration"
	"github.com/appgate/sdpctl/pkg/factory"
	"github.com/appgate/sdpctl/pkg/prompt"
	"github.com/spf13/viper"
)

type signInResponse struct {
	Token        string
	Expires      time.Time
	RefreshToken *string // todo
}

type Authenticate interface {
	// signin should include context with correct Accept header and provider metadata
	// if successful, it should return the bearer token and expiration date
	signin(ctx context.Context, provider openapi.InlineResponse20014Data) (*signInResponse, error)
}

// Signin is an interactive sign in function, that generates the config file
// Signin will show a interactive prompt to query the user for username, password and enter MFA if needed.
// and support SDPCTL_USERNAME & SDPCTL_PASSWORD environment variables.
// Signin supports MFA, compute a valid peer api version for selected appgate sdp collective.
func Signin(f *factory.Factory, remember, saveConfig bool) error {
	cfg := f.Config
	client, err := f.APIClient(cfg)
	if err != nil {
		return err
	}
	if cfg.DeviceID == "" {
		f.Config.DeviceID = configuration.DefaultDeviceID()
	}

	// if we already have a valid bearer token, we will continue without
	// without any additional checks.
	if cfg.ExpiredAtValid() && len(cfg.BearerToken) > 0 && !saveConfig {
		return nil
	}
	authenticator := NewAuth(client)
	// Get credentials from credentials file
	// Overwrite credentials with values set through environment variables

	loginOpts := openapi.LoginRequest{
		ProviderName: cfg.Provider,
		DeviceId:     cfg.DeviceID,
	}
	ctx := context.Background()
	acceptHeaderFormatString := "application/vnd.appgate.peer-v%d+json"
	// initial authtentication, this will fail, since we will use the singin response
	// to compute the correct peerVersion used in the selected appgate sdp collective.
	_, minMax, err := authenticator.Authentication(context.WithValue(ctx, openapi.ContextAcceptHeader, fmt.Sprintf(acceptHeaderFormatString, 5)), loginOpts)
	if err != nil && minMax == nil {
		return fmt.Errorf("invalid credentials %w", err)
	}
	if minMax != nil {
		viper.Set("api_version", minMax.Max)
		cfg.Version = int(minMax.Max)
	}

	acceptValue := fmt.Sprintf(acceptHeaderFormatString, minMax.Max)
	ctxWithAccept := context.WithValue(ctx, openapi.ContextAcceptHeader, acceptValue)
	providers, err := authenticator.ProviderNames(ctxWithAccept)
	if err != nil {
		return err
	}

	if len(providers) == 1 && len(loginOpts.ProviderName) <= 0 {
		loginOpts.ProviderName = providers[0].GetName()
	}
	providerMap := make(map[string]openapi.InlineResponse20014Data, 0)
	providerNames := make([]string, 0)
	for _, p := range providers {
		providerMap[p.GetName()] = p
		providerNames = append(providerNames, p.GetName())
	}

	if len(providers) > 1 && len(loginOpts.ProviderName) <= 0 {
		qs := &survey.Select{
			Message: "Choose a provider:",
			Options: providerNames,
		}
		if err := prompt.SurveyAskOne(qs, &loginOpts.ProviderName); err != nil {
			return err
		}
	}
	selectedProvider, ok := providerMap[loginOpts.ProviderName]
	if !ok {
		return fmt.Errorf("invalid provider '%s'", selectedProvider.GetName())
	}
	cfg.Provider = loginOpts.ProviderName
	var token *signInResponse
	switch selectedProvider.GetType() {
	case RadiusProvider:
	case LocalProvider:
		local := Local{
			Factory:    f,
			Remember:   remember,
			SaveConfig: saveConfig,
		}
		token, err = local.signin(ctxWithAccept, selectedProvider)
		if err != nil {
			return err
		}
	case OidcProvider:
		oidc := OpenIDConnect{
			Factory: f,
		}
		token, err = oidc.signin(ctxWithAccept, selectedProvider)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s identity provider is not supported", selectedProvider.GetType())
	}
	if token != nil {
		fmt.Println(token)
	}

	return nil
}
