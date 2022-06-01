package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	"github.com/appgate/sdpctl/pkg/factory"
	"github.com/google/uuid"
	"github.com/pkg/browser"
)

type OpenIDConnect struct {
	Factory *factory.Factory
}

type oIDCResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// oIDCError is the response body if we get HTTP 400-500 status code
type oIDCError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	Timestamp        string `json:"timestamp"`
	TraceID          string `json:"trace_id"`
	CorrelationID    string `json:"correlation_id"`
}

type indexHandler struct {
	RedirectURL string
}

func (h indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, h.RedirectURL, http.StatusSeeOther)
}

type oidcHandler struct {
	TokenURL, ClientID, CodeVerifier string
	Response                         chan oIDCResponse
	errors                           chan error
}

func (h oidcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if len(code) < 1 {
		w.WriteHeader(http.StatusInternalServerError)
		h.errors <- errors.New("missing code in parameter")
		return
	}

	form := url.Values{}
	form.Add("client_id", h.ClientID)
	form.Add("grant_type", "authorization_code")
	form.Add("redirect_uri", oidcRedirectAddress+"/oidc")
	form.Add("code_verifier", h.CodeVerifier)
	form.Add("code", code)
	req, err := http.NewRequest(http.MethodPost, h.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.errors <- err
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.errors <- err
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.errors <- err
		return
	}
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(http.StatusInternalServerError)
		var errResponse oIDCError
		if err = json.Unmarshal(body, &errResponse); err != nil {
			h.errors <- err
			return
		}
		fmt.Fprint(w, errResponse.ErrorDescription)
		h.errors <- fmt.Errorf("Oidc: %s - %s", errResponse.Error, errResponse.ErrorDescription)
		return
	}

	var data oIDCResponse
	if err = json.Unmarshal(body, &data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.errors <- err
		return
	}
	h.Response <- data
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, OpenIDConnectHTML)
}

func newSHACodeChallenge(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	size := hash.Size()

	sum := hash.Sum(nil)[:size]
	return base64.RawURLEncoding.EncodeToString(sum)
}

// oidcRedirectAddress is the local webserver for the redirect loop used with oidc provider
// it uses the same port as the appgate sdp client for consistency.
const (
	oidcPort            string = ":29001"
	oidcRedirectAddress string = "http://localhost" + oidcPort
)

func (o OpenIDConnect) signin(ctx context.Context, provider openapi.InlineResponse200Data) (*signInResponse, error) {
	mux := http.NewServeMux()
	tokenResponse := make(chan oIDCResponse)
	errorChan := make(chan error)
	server := &http.Server{
		Addr:    oidcPort,
		Handler: mux,
	}
	defer func() {
		server.Close()
		close(tokenResponse)
		close(errorChan)
	}()

	u, err := url.Parse(provider.GetAuthUrl())
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("scope", provider.GetScope())
	q.Set("client_id", provider.GetClientId())
	q.Set("state", "client")
	q.Set("redirect_uri", oidcRedirectAddress+"/oidc")
	codeVerifier := uuid.New().String()
	codeChallange := newSHACodeChallenge(codeVerifier)
	q.Set("code_challenge", codeChallange)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	mux.Handle("/", indexHandler{
		RedirectURL: u.String(),
	})
	mux.Handle("/oidc", oidcHandler{
		Response:     tokenResponse,
		errors:       errorChan,
		TokenURL:     provider.GetTokenUrl(),
		ClientID:     provider.GetClientId(),
		CodeVerifier: codeVerifier,
	})

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(os.Stderr, "[error] %s\n", err)
			}
		}
	}()
	browser.Stderr = io.Discard
	if err := browser.OpenURL(oidcRedirectAddress); err != nil {
		return nil, err
	}
	select {
	case err := <-errorChan:
		return nil, err
	case t := <-tokenResponse:
		// todo add t.RefreshToken
		fmt.Printf("%+v\n", t)
		// TODO patch upstream v17 api to include fixes in the api spec for
		// admin/authentication request body
		// TODO; do POST request  /admin/authentication
		// {
		//     "deviceId": "",
		//     "providerName": "Appgate Azure AD OIDC",
		//     "idToken": "",
		//     "accessToken": ""
		// }
		// the "token" from the response body is the valid one
		// then  HTTP GET https://appgate.company.com:8443/admin/authorization
		// the token
		// then do the OTP redirect dance once again. refactor from local?

		// https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#access-token-lifetime
		response := &signInResponse{
			Token:   t.AccessToken,
			Expires: time.Now().Local().Add(time.Second * time.Duration(t.ExpiresIn)),
		}
		return response, nil
	}
}
