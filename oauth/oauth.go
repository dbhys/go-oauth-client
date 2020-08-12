package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// Config is the configuration for an IDTokenVerifier.
type Config struct {
	Issuer             string `yaml:"issuer"`
	DefaultRedirectURI string `yaml:"defaultRedirectUri"`

	// If true, token expiry is not checked.
	SkipExpiryCheck bool `yaml:"skipExpiryCheck"`

	// SkipIssuerCheck is intended for specialized cases where the the caller wishes to
	// defer issuer validation. When enabled, callers MUST independently verify the Token's
	// Issuer is a known good value.
	//
	// Mismatched issuers often indicate client mis-configuration. If mismatches are
	// unexpected, evaluate if the provided issuer URL is incorrect instead of enabling
	// this option.
	SkipIssuerCheck bool `yaml:"skip_issuer_check"`
}

// Provider represents an OpenID Connect server's configuration.
type Provider struct {
	issuer     string
	authURL    string
	refreshURL string

	// Raw claims returned by the server.
	rawClaims    []byte
	algorithms   []string
	remoteKeySet KeySet
}

type cachedKeys struct {
	keys   []jose.JSONWebKey
	expiry time.Time
}

type providerJSON struct {
	Issuer     string   `json:"issuer,omitempty"`
	AuthURL    string   `json:"authorization_uri,omitempty"`
	RefreshURL string   `json:"refresh_uri,omitempty"`
	JWKSURL    string   `json:"jwks_uri,omitempty"`
	Algorithms []string `json:"token_signing_alg_values_supported,omitempty"`
}

// NewProvider uses the OpenID Connect discovery mechanism to construct a Provider.
//
// The issuer is the URL identifier for the service. For example: "https://accounts.google.com"
// or "https://login.salesforce.com".
func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/oauth-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to decode provider discovery object: %v", err)
	}

	if p.Issuer != issuer {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer, p.Issuer)
	}

	return &Provider{
		issuer:       p.Issuer,
		authURL:      p.AuthURL,
		refreshURL:   p.RefreshURL,
		rawClaims:    body,
		remoteKeySet: NewRemoteKeySet(ctx, p.JWKSURL),
	}, nil
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

// IDToken is an OpenID Connect extension that provides a predictable representation
// of an authorization event.
//
// The ID Token only holds fields OpenID Connect requires. To access additional
// claims returned by the server, use the Claims method.
type OAuthToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// A unique string which identifies the end user.
	Subject string
	// End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
	Name string
	// Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
	Nickname string
	Picture  string
	Email    string
	Gender   string
	// Expiry of the token. Ths package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time
	// When the token was issued by the provider.
	IssuedAt time.Time

	// Initial nonce provided during the authentication redirect.
	//
	// This package does NOT provided verification on the value of this field
	// and it's the user's responsibility to ensure it contains a valid value.
	Nonce string

	// at_hash claim, if set in the ID token. Callers can verify an access token
	// that corresponds to the ID token using the VerifyAccessToken method.
	AccessTokenHash string

	// signature algorithm used for ID token, needed to compute a verification hash of an
	// access token
	sigAlgorithm string

	// Raw payload of the id_token.
	claims []byte
}

type oAuthToken struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	UserName string   `json:"name"`
	Audience []string `json:"aud,omitempty"`
	Expiry   jsonTime `json:"exp"`
	IssuedAt jsonTime `json:"iat,omitempty"`
	Nonce    string   `json:"nonce,omitempty"`
	AtHash   string   `json:"at_hash,omitempty"`
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}
