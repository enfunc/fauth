package fauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"firebase.google.com/go/v4/auth"
	"github.com/enfunc/fauth"
)

func TestParseBearerValid(t *testing.T) {
	header := []string{
		"bearer token",
		"BEARER token",
		"bEaReR token",
	}
	for _, h := range header {
		if _, err := fauth.ParseBearer(h); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseBearerInvalid(t *testing.T) {
	header := []string{
		"",
		"token",
		"bearer ",
		"bearer  ",
		"welcome to the jungle",
	}
	for _, h := range header {
		if _, err := fauth.ParseBearer(h); err == nil {
			t.Fatalf("%s should be an invalid header", h)
		}
	}
}

func TestAuthData(t *testing.T) {
	ctx := context.Background()
	str := "dummy data"

	c := fauth.WithAuthData(ctx, str)
	s := fauth.AuthData(c)
	if s != str {
		t.Fatal("invalid auth data")
	}
}

func liveTestSetup(t *testing.T, f func(w *httptest.ResponseRecorder, r *http.Request, jwt string)) {
	t.Helper()

	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		t.Skip("GOOGLE_APPLICATION_CREDENTIALS missing")
	}
	jwt := os.Getenv("JWT")
	if jwt == "" {
		t.Skip("valid Firebase JWT env variable missing")
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("", "http://www.example.com", nil)
	r.Header.Set("Authorization", "Bearer "+jwt)
	f(w, r, jwt)
}

func TestVerifyIDToken(t *testing.T) {
	liveTestSetup(t, func(w *httptest.ResponseRecorder, r *http.Request, jwt string) {
		withFirebaseAuth, err := fauth.Auth(context.Background())
		if err != nil {
			t.Fatal(err)
			return
		}

		var data interface{}
		h := withFirebaseAuth(func(w http.ResponseWriter, r *http.Request) {
			data = fauth.AuthData(r.Context())
		})

		h.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("invalid status: %d", w.Code)
			return
		}
		token, ok := data.(*auth.Token)
		if !ok || token == nil {
			t.Fatal("invalid auth data")
			return
		}
	})
}

func TestVerifyIDTokenAndCheckRevoked(t *testing.T) {
	liveTestSetup(t, func(w *httptest.ResponseRecorder, r *http.Request, jwt string) {
		withFirebaseAuth, err := fauth.Auth(context.Background(), func(e *fauth.Engine) {
			e.OnAuth = fauth.VerifyIDTokenAndCheckRevoked
		})
		if err != nil {
			t.Fatal(err)
			return
		}

		var (
			token *auth.Token
			ok    bool
		)
		h := withFirebaseAuth(func(w http.ResponseWriter, r *http.Request) {
			token, ok = fauth.AuthToken(r.Context())
		})

		h.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("invalid status: %d", w.Code)
			return
		}
		if !ok || token == nil {
			t.Fatal("invalid auth data")
			return
		}
	})
}
