package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	"github.com/appgate/sdpctl/pkg/factory"
	"github.com/pkg/browser"
)

type Oidc struct {
	Factory              *factory.Factory
	Remember, SaveConfig bool
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
	http.Redirect(w, r, h.RedirectURL, http.StatusSeeOther)
}

type oidcHandler struct {
	Response chan string
}

func (h oidcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("OIDC response")
	fmt.Printf("Request %+v\n", r.RequestURI)
	q := r.URL.Query()
	code := q.Get("code")
	if len(code) < 1 {
		log.Println("Url Param 'code' is missing")
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
		log.Printf("request err1 %s\n", err)
		return
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("request err2 %s\n", err)
		return
	}
	fmt.Println(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("request err2 %s\n", err)
		return
	}
	var data oIDCResponse
	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Printf("request err2 %s\n", err)
		return
	}
	h.Response <- data.AccessToken
	fmt.Printf("Results: %+v\n", data)
}

func (o Oidc) Signin() error {

	tokenResponse := make(chan string)
	defer close(tokenResponse)
	mux := http.NewServeMux()
	// https://play.golang.com/p/4dP9k-hujEu
	new := "https://login.microsoftonline.com/b93e809a-49c5-4a0f-a606-82b846acc30d/oauth2/v2.0/authorize?client_id=6785aea6-7d09-43ba-9853-59af3a804c8e&code_challenge=qjrzSW9gMiUgpUvqgEPE4_-8swvyCtfOVvg55o5S_es&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A29001%2Foidc&response_type=code&scope=openid+profile+offline_access&state=client"
	mux.Handle("/", indexHandler{
		RedirectURL: new,
	})
	mux.Handle("/oidc", oidcHandler{
		Response: tokenResponse,
	})
	server := &http.Server{
		Addr:    ":29001",
		Handler: mux,
	}
	fmt.Println("===AAA==")
	defer server.Close()
	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("[err] %s\n", err) //stderr
		}
	}()
	if err := browser.OpenURL("http://localhost:29001"); err != nil {
		return err
	}

	t := <-tokenResponse
	customLoginResponse := &openapi.LoginResponse{
		Token: openapi.PtrString(t),
		// Expires: , //
	}
	fmt.Printf("foo %+v\n", customLoginResponse)
	return nil
}
