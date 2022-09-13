[![Go Reference](https://pkg.go.dev/badge/github.com/enfunc/fauth.svg)](https://pkg.go.dev/github.com/enfunc/fauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/enfunc/fauth)](https://goreportcard.com/report/github.com/enfunc/fauth)

# Fauth

`fauth` lets you create Firebase Auth middleware with ease. It's a simple wrapper of the [Firebase Admin Auth API](https://firebase.google.com/docs/auth/admin).

```shell
go get -u github.com/enfunc/fauth  
```  

Assuming you're following Google's advice and use the `GOOGLE_APPLICATION_CREDENTIALS`  environment variable to point to your service account, creating a middleware func is simple:

```go  
withFirebaseAuth, err := fauth.Auth(ctx)
if err != nil {
    log.Fatal(err)
}

http.HandleFunc("/private", withFirebaseAuth(func(w http.ResponseWriter, r *http.Request) {
    // The bearer token (JWT) in the Authorization header is valid.
    // To get the Firebase Token associated with the user, or other data you append to the
    // request Context via the `Engine.OnData` func, use the following:
    data := fauth.AuthData(r.Context())
    fmt.Printf("auth data: %v", data)
    
    w.Write([]byte("Hey, ma!"))
})) 
```  

You can also instantiate the Firebase app yourself:

```go  
withFirebaseAuth, err := fauth.Auth(ctx, func(e *fauth.Engine) {  
   e.NewApp = func(ctx context.Context) (*firebase.App, error) {  
      opt := option.WithCredentialsFile("path/to/refreshToken.json")  
      config := &firebase.Config{ProjectID: "my-project-id"}  
      return firebase.NewApp(ctx, config, opt)  
   }  
})
```

By default, `VerifyIDToken` func from the Firebase Admin SDK is used. This doesn't check for revoked or disabled tokens. Changing it and providing custom verification is easy:

```go
withFirebaseAuth, err := fauth.Auth(ctx, func(e *fauth.Engine) {  
   e.OnAuth = fauth.VerifyIDTokenAndCheckRevoked  
})
```

The default implementation returns a `401 Unauthorized` status code to the consumer on failure. To change it, override the `Engine.OnErr` func:

```go
withFirebaseAuth, err := fauth.Auth(ctx, func(e *fauth.Engine) {  
   e.OnErr = func(w http.ResponseWriter, r *http.Request, app *firebase.App, client *auth.Client, err error) {  
      // Customize error handling.  
  }  
})
```

Please open an issue or submit a pull request for any requests, bugs, or comments.

### License

MIT