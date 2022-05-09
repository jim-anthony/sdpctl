package auth

import (
	"context"
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

type indexHandler struct {
	RedirectURL string
}

func (h indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("INDEX URL")
	http.Redirect(w, r, h.RedirectURL, http.StatusSeeOther)
}

type oidcHandler struct {
	AuthURL, ClientID string
	Response          chan oIDCResponse
}

func (h oidcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("OpenID  URL")
	// fmt.Println("OIDC response")
	// fmt.Printf("Request %+v\n", r.RequestURI)
	q := r.URL.Query()
	code := q.Get("code")
	if len(code) < 1 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "[error] Missing code in parameter\n")
		return
	}

	form := url.Values{}
	form.Add("client_id", "6785aea6-7d09-43ba-9853-59af3a804c8e") // from provider list view
	form.Add("grant_type", "authorization_code")
	form.Add("redirect_uri", "http://localhost:29001/oidc")
	form.Add("code_verifier", "M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhakxifmZHag") // generate custom for each, base on machine id?
	form.Add("code", code)
	req, err := http.NewRequest(http.MethodPost, "https://login.microsoftonline.com/b93e809a-49c5-4a0f-a606-82b846acc30d/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "[error] could not siginin %s\n", err)
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "[error] could not do request %s\n", err)
		return
	}
	fmt.Println(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "[error] could not read response body %s\n", err)
		return
	}
	var data oIDCResponse
	err = json.Unmarshal(body, &data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "[error] could not parse body %s\n", err)
		return
	}
	h.Response <- data
	fmt.Printf("Results: %+v\n", data)
	fmt.Fprint(w, OpenIDConnectHTML)
}

func (o OpenIDConnect) signin(ctx context.Context, provider openapi.InlineResponse20014Data) (*signInResponse, error) {
	tokenResponse := make(chan oIDCResponse)
	defer close(tokenResponse)
	mux := http.NewServeMux()
	// https://play.golang.com/p/4dP9k-hujEu
	// new := "https://login.microsoftonline.com/b93e809a-49c5-4a0f-a606-82b846acc30d/oauth2/v2.0/authorize?client_id=6785aea6-7d09-43ba-9853-59af3a804c8e&code_challenge=qjrzSW9gMiUgpUvqgEPE4_-8swvyCtfOVvg55o5S_es&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A29001%2Foidc&response_type=code&scope=openid+profile+offline_access&state=client"
	new := "https://google.se"
	mux.Handle("/", indexHandler{
		RedirectURL: new,
	})
	mux.Handle("/oidc", oidcHandler{
		Response: tokenResponse,
		// AuthURL:
	})
	server := &http.Server{
		Addr:    ":29001",
		Handler: mux,
	}
	defer server.Close()
	go func() {
		if err := server.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(os.Stderr, "[error] %s\n", err)
			}
		}
	}()
	browser.Stderr = io.Discard
	if err := browser.OpenURL("http://localhost:29001"); err != nil {
		return nil, err
	}

	t := <-tokenResponse
	// todo add t.RefreshToken
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#access-token-lifetime
	response := &signInResponse{
		Token:   t.AccessToken,
		Expires: time.Now().Local().Add(time.Second * time.Duration(t.ExpiresIn)),
	}
	return response, nil
}
