package providers

import (
	"context"
	"errors"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// CivoProvider represents a Civo based Identity Provider
type CivoProvider struct {
	*ProviderData
	Team string
}

var _ Provider = (*CivoProvider)(nil)

const (
	CivoProviderName = "civo"
	CivoDefaultScope = "read"
)

var (
	// Default Login URL for Civo.
	// Pre-parsed URL of https://cloud.Civo.com/v1/oauth/authorize.
	CivoDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "auth.civo.com",
		Path:   "authorize",
	}

	// Default Redeem URL for Civo.
	// Pre-parsed URL of  https://cloud.Civo.com/v1/oauth/token.
	CivoDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "auth.civo.com",
		Path:   "token",
	}

	// Default Profile URL for Civo.
	// Pre-parsed URL of https://cloud.Civo.com/v2/account.
	CivoDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "auth.civo.com",
		Path:   "userinfo",
	}
)

// NewCivoProvider initiates a new CivoProvider
func NewCivoProvider(p *ProviderData, opts options.CivoOptions) *CivoProvider {
	p.setProviderDefaults(providerDefaults{
		name:        CivoProviderName,
		loginURL:    CivoDefaultLoginURL,
		redeemURL:   CivoDefaultRedeemURL,
		profileURL:  CivoDefaultProfileURL,
		validateURL: CivoDefaultProfileURL,
		scope:       CivoDefaultScope,
	})
	p.getAuthorizationHeaderFunc = makeOIDCHeader

	return &CivoProvider{ProviderData: p, Team: opts.Team}
}

// GetEmailAddress returns the Account email address
func (p *CivoProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return "", err
	}

	email, err := json.GetPath("email").String()
	if err != nil {
		return "", err
	}

	// p.setTeam(team)

	return email, nil
}

// ValidateSession validates the AccessToken
func (p *CivoProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

// EnrichSession updates the User & Email after the initial Redeem
func (p *CivoProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if s.AccessToken == "" {
		return errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return err
	}

	team, err := json.GetPath("team_id").String()
	if err != nil {
		return err
	}

	if team != p.Team {
		return errors.New("user isn't part of the required team")
	}

	s.Groups = append(s.Groups, team)

	return nil
}
