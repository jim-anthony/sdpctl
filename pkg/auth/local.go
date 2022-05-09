package auth

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	appliancepkg "github.com/appgate/sdpctl/pkg/appliance"
	"github.com/appgate/sdpctl/pkg/configuration"
	"github.com/appgate/sdpctl/pkg/factory"
	"github.com/appgate/sdpctl/pkg/keyring"
	"github.com/appgate/sdpctl/pkg/prompt"
	"github.com/pkg/browser"
	"github.com/spf13/viper"
)

type Local struct {
	Factory              *factory.Factory
	Remember, SaveConfig bool
}

func (l Local) signin(ctx context.Context, provider openapi.InlineResponse20014Data) (*signInResponse, error) {
	cfg := l.Factory.Config

	// Clear old credentials if remember me flag is provided
	if l.Remember {
		if err := cfg.ClearCredentials(); err != nil {
			return nil, err
		}
	}
	host, err := cfg.GetHost()
	if err != nil {
		return nil, err
	}
	client, err := l.Factory.APIClient(cfg)
	if err != nil {
		return nil, err
	}
	authenticator := NewAuth(client)
	credentials, err := cfg.LoadCredentials()
	if err != nil {
		return nil, err
	}
	loginOpts := openapi.LoginRequest{
		ProviderName: cfg.Provider,
		DeviceId:     cfg.DeviceID,
	}

	if len(credentials.Username) <= 0 {
		err := prompt.SurveyAskOne(&survey.Input{
			Message: "Username:",
		}, &credentials.Username, survey.WithValidator(survey.Required))
		if err != nil {
			return nil, err
		}
	}
	if len(credentials.Password) <= 0 {
		err := prompt.SurveyAskOne(&survey.Password{
			Message: "Password:",
		}, &credentials.Password, survey.WithValidator(survey.Required))
		if err != nil {
			return nil, err
		}
	}

	if l.Remember {
		if err := rememberCredentials(cfg, credentials); err != nil {
			return nil, fmt.Errorf("Failed to store credentials: %w", err)
		}
	}
	loginOpts.Username = openapi.PtrString(credentials.Username)
	loginOpts.Password = openapi.PtrString(credentials.Password)

	loginResponse, _, err := authenticator.Authentication(ctx, loginOpts)
	if err != nil {
		return nil, err
	}
	authToken := fmt.Sprintf("Bearer %s", loginResponse.GetToken())
	_, err = authenticator.Authorization(ctx, authToken)
	if errors.Is(err, ErrPreConditionFailed) {
		otp, err := authenticator.InitializeOTP(ctx, loginOpts.GetPassword(), authToken)
		if err != nil {
			return nil, err
		}
		testOTP := func() (*openapi.LoginResponse, error) {
			var answer string
			optKey := &survey.Password{
				Message: "Please enter your one-time password:",
			}
			if err := prompt.SurveyAskOne(optKey, &answer, survey.WithValidator(survey.Required)); err != nil {
				return nil, err
			}
			return authenticator.PushOTP(ctx, answer, authToken)
		}
		// TODO add support for RadiusChallenge, Push
		switch otpType := otp.GetType(); otpType {
		case "Secret":
			barcodeFile, err := BarcodeHTMLfile(otp.GetBarcode(), otp.GetSecret())
			if err != nil {
				return nil, err
			}
			fmt.Printf("\nOpen %s to scan the barcode to your authenticator app\n", barcodeFile.Name())
			fmt.Printf("\nIf you can’t use the barcode, enter %s in your authenticator app\n", otp.GetSecret())
			if err := browser.OpenURL(barcodeFile.Name()); err != nil {
				return nil, err
			}
			defer os.Remove(barcodeFile.Name())
			fallthrough

		case "AlreadySeeded":
			fallthrough
		default:
			// Give the user 3 attempts to enter the correct OTP key
			for i := 0; i < 3; i++ {
				newToken, err := testOTP()
				if err != nil {
					if errors.Is(err, ErrInvalidOneTimePassword) {
						fmt.Println(err)
						continue
					}
				}
				if newToken != nil {
					authToken = fmt.Sprintf("Bearer %s", newToken.GetToken())
					break
				}
			}
		}
	} else if err != nil {
		return nil, err
	}
	authorizationToken, err := authenticator.Authorization(ctx, authToken)
	if err != nil {
		return nil, err
	}

	cfg.BearerToken = authorizationToken.GetToken()
	cfg.ExpiresAt = authorizationToken.Expires.String()
	if err := keyring.SetBearer(host, cfg.BearerToken); err != nil {
		return nil, fmt.Errorf("could not store token in keychain %w", err)
	}

	viper.Set("provider", cfg.Provider)
	viper.Set("expires_at", cfg.ExpiresAt)
	viper.Set("url", cfg.URL)

	a, err := l.Factory.Appliance(cfg)
	if err != nil {
		return nil, err
	}
	allAppliances, err := a.List(ctx, nil)
	if err != nil {
		return nil, err
	}
	primaryController, err := appliancepkg.FindPrimaryController(allAppliances, host)
	if err != nil {
		return nil, err
	}
	stats, _, err := a.Stats(ctx)
	if err != nil {
		return nil, err
	}
	v, err := appliancepkg.GetApplianceVersion(*primaryController, stats)
	if err != nil {
		return nil, err
	}
	viper.Set("primary_controller_version", v.String())
	if l.SaveConfig {
		if err := viper.WriteConfig(); err != nil {
			return nil, err
		}
	}
	response := &signInResponse{}
	return response, nil
}

func rememberCredentials(cfg *configuration.Config, credentials *configuration.Credentials) error {
	q := []*survey.Question{
		{
			Name: "remember",
			Prompt: &survey.Select{
				Message: "What credentials should be saved?",
				Options: []string{"both", "only username", "only password"},
				Default: "both",
			},
		},
	}

	answers := struct {
		Remember string `survey:"remember"`
	}{}

	if err := survey.Ask(q, &answers); err != nil {
		return err
	}

	credentialsCopy := &configuration.Credentials{}
	switch answers.Remember {
	case "only username":
		credentialsCopy.Username = credentials.Username
	case "only password":
		credentialsCopy.Password = credentials.Password
	default:
		credentialsCopy.Username = credentials.Username
		credentialsCopy.Password = credentials.Password
	}

	if err := cfg.StoreCredentials(credentialsCopy); err != nil {
		return err
	}

	return nil
}
