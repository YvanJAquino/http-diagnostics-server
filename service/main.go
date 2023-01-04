// Created with Strapit
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net/http"
	"net/url"

	"google.golang.org/api/idtoken"
)

var lg = log.New(os.Stderr, "", 0)
var PORT = os.Getenv("PORT")

func main() {
	ctx := context.Background()
	v, err := idtoken.NewValidator(ctx)
	if err != nil {
		log.Println("error during Validator instantiation")
		log.Fatal(err)
	}
	requestAuditor := func(w http.ResponseWriter, r *http.Request) {
		audited := new(Request)
		authHeader := r.Header.Get("Authorization")

		if authHeader != "" {
			idToken := extractToken(authHeader)
			p, err := v.Validate(ctx, idToken, "")
			if err != nil {
				log.Println("error during Validation")
				log.Fatal(err)
			}
			auth := &AuthPayload{
				Audience: p.Audience,
				Claims:   p.Claims,
				Expires:  p.Expires,
				IssuedAt: p.IssuedAt,
				Issuer:   p.Issuer,
				Subject:  p.Subject,
			}
			audited.AuthPayload = auth
		}
		audited.ContentLength = r.ContentLength
		audited.Form = r.Form
		audited.Header = r.Header
		audited.Host = r.Host
		audited.Method = r.Method
		audited.Proto = r.Proto
		audited.ProtoMajor = r.ProtoMajor
		audited.ProtoMinor = r.ProtoMinor
		audited.RemoteAddr = r.RemoteAddr
		audited.RequestURI = r.RequestURI
		audited.URL = r.URL
		audited.Cookies = r.Cookies()

		enc := json.NewEncoder(lg.Writer())
		err := enc.Encode(audited)
		if err != nil {
			log.Println("error during json.Encode")
			log.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	server := &http.Server{
		Addr:    ":" + PORT,
		Handler: http.HandlerFunc(requestAuditor),
	}

	go func() {
		log.Printf("Serving HTTP on :%s", PORT)
		err := server.ListenAndServe()
		log.Println(err)
		if err != nil && err != http.ErrServerClosed {
			os.Exit(1)
		}
	}()

	sig := <-signals
	log.Printf("%s signal received: initiating graceful shutdown", sig)
	shut, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = server.Shutdown(shut)
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func extractToken(header string) string {
	authHeaderParts := strings.Split(header, " ")
	return authHeaderParts[1]
}

type AuthPayload struct {
	Audience string         `json:"audience,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	Expires  int64          `json:"expires,omitempty"`
	IssuedAt int64          `json:"issuedAt,omitempty"`
	Issuer   string         `json:"issuer,omitempty"`
	Subject  string         `json:"subject,omitempty"`
}

type Request struct {
	ContentLength int64          `json:"contentLength,omitempty"`
	Form          url.Values     `json:"form,omitempty"`
	Header        http.Header    `json:"header,omitempty"`
	Host          string         `json:"host,omitempty"`
	Method        string         `json:"method,omitempty"`
	Proto         string         `json:"proto,omitempty"`
	ProtoMajor    int            `json:"protoMajor,omitempty"`
	ProtoMinor    int            `json:"protoMinor,omitempty"`
	RemoteAddr    string         `json:"remoteAddr,omitempty"`
	RequestURI    string         `json:"requestUri,omitempty"`
	URL           *url.URL       `json:"url,omitempty"`
	Cookies       []*http.Cookie `json:"cookies,omitempty"`
	AuthPayload   *AuthPayload   `json:"authPayload,omitempty"`
}

func NewRequest() *Request {
	req := new(Request)
	req.Form = url.Values{}
	req.Header = http.Header{}
	req.URL = &url.URL{}
	req.Cookies = make([]*http.Cookie, 0)

	return req
}

type Claim map[string]string
