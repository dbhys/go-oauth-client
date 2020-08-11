package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	jose "gopkg.in/square/go-jose.v2"
	"strings"
	"time"
)

// KeySet is a set of publc JSON Web Keys that can be used to validate the signature
// of JSON web tokens. This is expected to be backed by a remote key set through
// provider metadata discovery or an in-memory set of keys delivered out-of-band.
type KeySet interface {
	// VerifySignature parses the JSON web token, verifies the signature, and returns
	// the raw payload. Header and claim fields are validated by other parts of the
	// package. For example, the KeySet does not need to check values such as signature
	// algorithm, issuer, and audience since the IDTokenVerifier validates these values
	// independently.
	//
	// If VerifySignature makes HTTP requests to verify the token, it's expected to
	// use any HTTP client associated with the context through ClientContext.
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

// IDTokenVerifier provides verification for ID Tokens.
type TokenVerifier struct {
	provider *Provider
	config   *Config
}

func NewVerifier(config *Config, provider *Provider) *TokenVerifier {
	return &TokenVerifier{config: config, provider: provider}
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

func contains(sli []string, ele string) bool {
	for _, s := range sli {
		if s == ele {
			return true
		}
	}
	return false
}

func parseClaim(raw []byte, name string, v interface{}) error {
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return err
	}

	val, ok := parsed[name]
	if !ok {
		return fmt.Errorf("claim doesn't exist: %s", name)
	}

	return json.Unmarshal([]byte(val), v)
}

func (v *TokenVerifier) Verify(ctx context.Context, rawToken string) (*OAuthToken, error) {
	jws, err := jose.ParseSigned(rawToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}

	// Throw out tokens with invalid claims before trying to verify the token. This lets
	// us do cheap checks before possibly re-syncing keys.
	payload, err := parseJWT(rawToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	var token oAuthToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
	}

	t := &OAuthToken{
		Issuer:          token.Issuer,
		Subject:         token.Subject,
		Audience:        token.Audience,
		Expiry:          time.Time(token.Expiry),
		IssuedAt:        time.Time(token.IssuedAt),
		Nonce:           token.Nonce,
		AccessTokenHash: token.AtHash,
		claims:          payload,
	}

	// Check issuer.
	if !v.config.SkipIssuerCheck && t.Issuer != v.provider.issuer {
		return nil, fmt.Errorf("oidc: id token issued by a different provider, expected %q got %q", v.provider.issuer, t.Issuer)
	}

	// If a SkipExpiryCheck is false, make sure token is not expired.
	if !v.config.SkipExpiryCheck {

		nowTime := time.Now()

		if t.Expiry.Before(nowTime) {
			return nil, fmt.Errorf("oidc: token is expired (Token Expiry: %v)", t.Expiry)
		}

	}

	switch len(jws.Signatures) {
	case 0:
		return nil, fmt.Errorf("token not signed")
	case 1:
	default:
		return nil, fmt.Errorf("multiple signatures on id token not supported")
	}

	sig := jws.Signatures[0]
	supportedSigAlgs := v.provider.algorithms
	if len(supportedSigAlgs) == 0 {
		supportedSigAlgs = []string{RS256}
	}

	if !contains(supportedSigAlgs, sig.Header.Algorithm) {
		return nil, fmt.Errorf("oidc: id token signed with unsupported algorithm, expected %q got %q", supportedSigAlgs, sig.Header.Algorithm)
	}

	t.sigAlgorithm = sig.Header.Algorithm

	gotPayload, err := v.provider.remoteKeySet.VerifySignature(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %v", err)
	}

	// Ensure that the payload returned by the square actually matches the payload parsed earlier.
	if !bytes.Equal(gotPayload, payload) {
		return nil, errors.New("oidc: internal error, payload parsed did not match previous payload")
	}

	return t, nil
}
