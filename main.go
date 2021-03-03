package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type vippsClaims struct {
	Accounts       []vippsAccount `json:"accounts"`
	Address        vippsAddress   `json:"address"`
	BirthDate      string         `json:"birthdate"`
	Email          string         `json:"email"`
	EmailVerified  bool           `json:"email_verified"`
	FamilyName     string         `json:"family_name"`
	GivenName      string         `json:"given_name"`
	Name           string         `json:"name"`
	NIN            string         `json:"nin"`
	OtherAddresses []vippsAddress `json:"other_addresses"`
	PhoneNumber    string         `json:"phone_number"`
	UID            string         `json:"sub"`
}

type vippsAccount struct {
	AccountName   string `json:"account_name"`
	AccountNumber string `json:"account_number"`
	BankName      string `json:"bank_name"`
}

type vippsAddress struct {
	StreetAddress string `json:"street_address"`
	PostalCode    string `json:"postal_code"`
	Region        string `json:"region"`
	Country       string `json:"country"`
	Formatted     string `json:"formatted"`
	AddressType   string `json:"address_type"`
}

type vippsEnvironment int

const (
	vippsEnvironmentTest vippsEnvironment = iota
	vippsEnvironmentProduction
)

func (ve vippsEnvironment) baseURL() string {
	switch ve {
	case vippsEnvironmentProduction:
		return "https://api.vipps.no/access-management-1.0/access/"
	default:
		return "https://apitest.vipps.no/access-management-1.0/access/"
	}
}

func newVippsEnvironment(env string) vippsEnvironment {
	switch env {
	case "prod", "production":
		return vippsEnvironmentProduction
	default:
		return vippsEnvironmentTest
	}
}

type vippsConfig struct {
	addr                   string
	clientID, clientSecret string
	env                    vippsEnvironment
	port                   string
	redirectURL            string
	scopes                 []string
}

func main() {
	env := flag.String("env", "test", "vipps environment")
	clientID := flag.String("client_id", "", "vipps client id")
	clientSecret := flag.String("client_secret", "", "vipps client secret")
	openidScopes := flag.String("openid_scopes", "name,email", "requested openid scopes (comma separated)")
	redirectURL := flag.String("redirect", "http://127.0.0.1:8080/callback", "redirect url")
	port := flag.String("port", "8080", "port to listen on")
	listenAddr := flag.String("addr", "127.0.0.1", "addr to listen on")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, vippsConfig{
		addr:         *listenAddr,
		env:          newVippsEnvironment(*env),
		clientID:     *clientID,
		clientSecret: *clientSecret,
		port:         *port,
		redirectURL:  *redirectURL,
		scopes:       strings.Split(*openidScopes, ","),
	}); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, config vippsConfig) error {
	provider, err := oidc.NewProvider(ctx, config.env.baseURL())
	if err != nil {
		return err
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.clientID,
	})

	oauthConfig := oauth2.Config{
		ClientID:     config.clientID,
		ClientSecret: config.clientSecret,
		RedirectURL:  config.redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.scopes,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			state, err := generateRandomStringURLSafe(32)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "state",
				Value:    state,
				MaxAge:   5 * 60,
				HttpOnly: true,
				Path:     "/",
				Secure:   false,
			})

			http.Redirect(w, r, oauthConfig.AuthCodeURL(state), http.StatusSeeOther)
			return
		}

		if err := template.Must(template.New("").Parse(`<html>
<body>
	<form method="post">
		<input type="submit" value="Login"/>
	</form>
</body>
</html>
`)).Execute(w, nil); err != nil {
			log.Printf("template.Execute: err=%v\n", err)
		}
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if errorMsg := r.Form.Get("error"); errorMsg != "" {
			http.Error(w, fmt.Sprintf("error=%q description=%q hint=%q", errorMsg, r.Form.Get("error_description"), r.Form.Get("error_hint")), http.StatusInternalServerError)
			return
		}

		code := r.Form.Get("code")
		state := r.Form.Get("state")
		savedState, err := r.Cookie("state")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if savedState.Value != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}

		token, err := oauthConfig.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id token in response", http.StatusBadRequest)
			return
		}

		_, err = verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		claims := vippsClaims{}
		if err := userInfo.Claims(&claims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    rawIDToken,
			Path:     "/",
			MaxAge:   5 * 60,
			HttpOnly: true,
		})

		if err := template.Must(template.New("").Parse(`
<html>
<body>
	<p>Logged in as {{.UID}}</p>
	<p>Some claims from /userinfo:</p>
	<pre>
Name: {{.Name}}
Email: {{.Email}}
Phone: {{.PhoneNumber}}
	</pre>
	<a href="/authenticated">Do authenticated call</a>
</body>
</html>`)).Execute(w, claims); err != nil {
			log.Printf("template.Execute: err=%v", err)
		}
	})

	mux.HandleFunc("/authenticated", func(w http.ResponseWriter, r *http.Request) {
		tokenCookie, err := r.Cookie("token")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if _, err := verifier.Verify(r.Context(), tokenCookie.Value); err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if err := template.Must(template.New("").Parse(`
<html>
<body>
<p>Success!</p>
</body>
</html>`)).Execute(w, nil); err != nil {
			log.Printf("template.Execute: err=%v", err)
		}
	})

	srv := http.Server{
		Addr:         strings.Join([]string{config.addr, config.port}, ":"),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		select {
		case <-ctx.Done():
			srv.Shutdown(context.Background())
		}
	}()

	return srv.ListenAndServe()
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func generateRandomStringURLSafe(n int) (string, error) {
	b, err := generateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}
