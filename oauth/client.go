package oauth

import "context"

type Client struct {
	Config   *Config
	Provider *Provider
	Verifier *TokenVerifier
}

func NewClient(ctx context.Context, oauthConf *Config) (*Client, error) {
	provider, err := NewProvider(ctx, oauthConf.Issuer)
	if err != nil {
		return nil, err
	}

	verifier := NewVerifier(oauthConf, provider)

	return &Client{Config: oauthConf, Provider: provider, Verifier: verifier}, nil
}

func (c *Client) AuthUrl(redirectUri string) string {
	if redirectUri == "" {
		return c.Provider.authURL + "?redirect_uri=" + c.Config.DefaultRedirectURI
	}
	return c.Provider.authURL + "?redirect_uri=" + redirectUri
}
