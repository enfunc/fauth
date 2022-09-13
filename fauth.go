package fauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

// Bearer returns the bearer token from the Authorization header of the `http.Request`.
func Bearer(r *http.Request) (string, error) {
	return ParseBearer(r.Header.Get("Authorization"))
}

// ParseBearer parses the Authorization header string and returns the bearer value.
// It expects it to be of form `Bearer eyJhbGciOi`...
func ParseBearer(header string) (string, error) {
	t := strings.Split(header, " ")
	if len(t) != 2 || len(t[1]) == 0 || strings.ToLower(t[0]) != "bearer" {
		return "", fmt.Errorf("fauth: invalid header: %s", header)
	}
	return t[1], nil
}

// VerifyIDToken verifies the request is coming from a valid Firebase user.
// It does not check whether the token has been revoked or disabled, use `VerifyIDTokenAndCheckRevoked`
// if a revocation check is needed.
func VerifyIDToken(r *http.Request, app *firebase.App, client *auth.Client) (any, error) {
	jwt, err := Bearer(r)
	if err != nil {
		return nil, err
	}
	token, err := client.VerifyIDToken(r.Context(), jwt)
	if err != nil {
		return nil, fmt.Errorf("fauth: failed to verify the token: %w", err)
	}
	return token, nil
}

// VerifyIDTokenAndCheckRevoked verifies the request is coming from a valid Firebase user
// and the token hasn't been revoked.
//
// Unlike `VerifyIDToken`, this function must make an RPC call to perform the revocation check.
// Developers are advised to take this additional overhead into consideration when including this
// function in an authorization flow that gets executed often.
//
// Here's an example on how to use it:
//
//	withFirebaseAuth, err := fauth.Auth(ctx, func(e *fauth.Engine) {
//		e.OnAuth = fauth.VerifyIDTokenAndCheckRevoked
//	})
func VerifyIDTokenAndCheckRevoked(r *http.Request, app *firebase.App, client *auth.Client) (any, error) {
	jwt, err := Bearer(r)
	if err != nil {
		return nil, err
	}
	token, err := client.VerifyIDTokenAndCheckRevoked(r.Context(), jwt)
	if err != nil {
		return nil, fmt.Errorf("fauth: failed to verify the token: %w", err)
	}
	return token, nil
}

type contextKey string

const authDataContextKey contextKey = "data"

// AuthData returns the auth data associated with the verification request.
func AuthData(ctx context.Context) any {
	return ctx.Value(authDataContextKey)
}

// WithAuthData returns a copy of the `context.Context` with the given data.
// To retrieve it, use the `AuthData` func.
func WithAuthData(ctx context.Context, data any) context.Context {
	return context.WithValue(ctx, authDataContextKey, data)
}

// AuthToken returns the Firebase Token.
// This assumes the stock Firebase Token is returned by the `Engine.OnAuth` func.
func AuthToken(ctx context.Context) (*auth.Token, bool) {
	token, ok := AuthData(ctx).(*auth.Token)
	return token, ok
}

func defaultNewApp(ctx context.Context) (*firebase.App, error) {
	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase app: %w", err)
	}
	return app, nil
}

func defaultOnData(r *http.Request, data any) (*http.Request, error) {
	ctx := WithAuthData(r.Context(), data)
	return r.WithContext(ctx), nil
}

func defaultOnErr(w http.ResponseWriter, r *http.Request, app *firebase.App, client *auth.Client, err error) {
	w.WriteHeader(http.StatusUnauthorized)
}

// Option allows you to override the Engine defaults, e.g.:
//
//	withFirebaseAuth, err := fauth.Auth(ctx, func(e *fauth.Engine) {
//		e.NewApp = func(ctx context.Context) (*firebase.App, error) {
//			opt := option.WithCredentialsFile("path/to/refreshToken.json")
//			config := &firebase.Config{ProjectID: "my-project-id"}
//			return firebase.NewApp(ctx, config, opt)
//		}
//	})
type Option func(*Engine)

type Engine struct {
	NewApp func(ctx context.Context) (*firebase.App, error)
	OnAuth func(r *http.Request, app *firebase.App, client *auth.Client) (any, error)
	OnData func(r *http.Request, data any) (*http.Request, error)
	OnErr  func(w http.ResponseWriter, r *http.Request, app *firebase.App, client *auth.Client, err error)
}

// Auth returns a middleware func verifying the request is coming from a valid Firebase user.
// For example:
//
//	withFirebaseAuth, err := fauth.Auth(ctx)
//	if err != nil {
//		t.Fatal(err)
//	}
//	http.HandleFunc("/private", withFirebaseAuth(func(w http.ResponseWriter, r *http.Request) {
//		// If we're here, the bearer token in the Authorization header is valid.
//		w.Write([]byte("Hey, ma!"))
//	}))
func Auth(ctx context.Context, opts ...Option) (func(http.HandlerFunc) http.HandlerFunc, error) {
	engine := &Engine{}
	for _, opt := range opts {
		opt(engine)
	}
	if engine.NewApp == nil {
		engine.NewApp = defaultNewApp
	}
	if engine.OnAuth == nil {
		engine.OnAuth = VerifyIDToken
	}
	if engine.OnData == nil {
		engine.OnData = defaultOnData
	}
	if engine.OnErr == nil {
		engine.OnErr = defaultOnErr
	}
	app, err := engine.NewApp(ctx)
	if err != nil {
		return nil, fmt.Errorf("fauth: error initializing firebase: %w", err)
	}
	cli, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("fauth: error initializing firebase auth: %w", err)
	}
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			data, err := engine.OnAuth(r, app, cli)
			if err != nil {
				engine.OnErr(w, r, app, cli, err)
				return
			}
			req, err := engine.OnData(r, data)
			if err != nil {
				engine.OnErr(w, r, app, cli, err)
				return
			}
			h.ServeHTTP(w, req)
		}
	}, nil
}
