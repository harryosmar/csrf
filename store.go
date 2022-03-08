//go:build go1.11
// +build go1.11

package csrf

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

// store represents the session storage used for CSRF tokens.
type Store interface {
	// Get returns the real CSRF token from the store.
	Get(*http.Request) ([]byte, error)
	// Save stores the real CSRF token in the store and writes a
	// cookie to the http.ResponseWriter.
	// For non-cookie stores, the cookie should contain a unique (256 bit) ID
	// or key that references the token in the backend store.
	// csrf.GenerateRandomBytes is a helper function for generating secure IDs.
	Save(token []byte, w http.ResponseWriter) error
}

// CookieStore is a signed cookie session store for CSRF tokens.
type CookieStore struct {
	Name     string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	Path     string
	Domain   string
	Sc       *securecookie.SecureCookie
	SameSite SameSiteMode
}

// Get retrieves a CSRF token from the session cookie. It returns an empty token
// if decoding fails (e.g. HMAC validation fails or the named cookie doesn't exist).
func (cs *CookieStore) Get(r *http.Request) ([]byte, error) {
	// Retrieve the cookie from the request
	cookie, err := r.Cookie(cs.Name)
	if err != nil {
		return nil, err
	}

	token := make([]byte, tokenLength)
	// Decode the HMAC authenticated cookie.
	err = cs.Sc.Decode(cs.Name, cookie.Value, &token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// Save stores the CSRF token in the session cookie.
func (cs *CookieStore) Save(token []byte, w http.ResponseWriter) error {
	// Generate an encoded cookie value with the CSRF token.
	encoded, err := cs.Sc.Encode(cs.Name, token)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     cs.Name,
		Value:    encoded,
		MaxAge:   cs.MaxAge,
		HttpOnly: cs.HttpOnly,
		Secure:   cs.Secure,
		SameSite: http.SameSite(cs.SameSite),
		Path:     cs.Path,
		Domain:   cs.Domain,
	}

	// Set the Expires field on the cookie based on the MaxAge
	// If MaxAge <= 0, we don't set the Expires attribute, making the cookie
	// session-only.
	if cs.MaxAge > 0 {
		cookie.Expires = time.Now().Add(
			time.Duration(cs.MaxAge) * time.Second)
	}

	// Write the authenticated cookie to the response.
	http.SetCookie(w, cookie)

	return nil
}
