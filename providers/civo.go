package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// CivoProvider represents a Civo based Identity Provider
type CivoProvider struct {
	*ProviderData
	// Account is the account_id to restrict access to
	Account string
	// PermissionsMap is the map of permissions to restrict access to
	PermissionsMap map[string]struct{}
	// PermissionsURL is the url to verify the user permissions in the specified account
	PermissionsURL string
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
		Path:   "v2/authorize",
	}

	// Default Redeem URL for Civo.
	// Pre-parsed URL of  https://cloud.Civo.com/v1/oauth/token.
	CivoDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "auth.civo.com",
		Path:   "v2/token",
	}

	// Default Profile URL for Civo.
	// Pre-parsed URL of https://cloud.Civo.com/v2/account.
	CivoDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "auth.civo.com",
		Path:   "v2/userinfo",
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

	// using a map to avoid nested cycle to every request. The key of the map is the permission string
	requiredPermissionsMap := make(map[string]struct{}, 0)
	for _, perm := range opts.Permissions {
		requiredPermissionsMap[perm] = struct{}{}
	}
	/*
		    map[string] struct{}{
				"*.*": struct{}{},
				"compute.*": struct{}{},
				"compute.updater": struct{}{},
			}
	*/

	fmt.Printf("DEBUG -  Civo - Composed Permissions Map %+v\n", requiredPermissionsMap)

	return &CivoProvider{
		ProviderData:   p,
		Account:        opts.Account,           // owner of the namespace in which this pod lives (and the respective instance you would like to have access to)
		PermissionsMap: requiredPermissionsMap, // static map of permissions initially passed as flags from the civo-operation-operator
		PermissionsURL: opts.PermissionsURL,    // api permissions url to fetch if the user under this account has real-time permissions to perform a VNC access
	}
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

	fmt.Printf("DEBUG - Civo: provider.ProfileURL %s\n", p.ProfileURL.String())

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return err
	}

	user, err := json.GetPath("user_id").String()
	if err != nil {
		return err
	}

	fmt.Printf("DEBUG - Civo: EnrichSession user %s\n", user)

	permissions, err := p.getUserPermissionsInAccount(ctx, s.AccessToken)
	if err != nil {
		fmt.Printf("DEBUG - Civo: EnrichSession get user permissions retuned an error %s \n", err.Error())
		return err
	}

	fmt.Printf("DEBUG - Civo: EnrichSession permissions %s \n", permissions)

	if !p.isUserAllowed(permissions) {
		return fmt.Errorf("user %s in account %s has no sufficient permissions", user, p.Account)
	}

	fmt.Printf("DEBUG - Civo: EnrichSession user %s is allowed to VNC into account %s \n", user, p.Account)

	s.Groups = append(s.Groups, p.Account) // FIXME: is that correct? What is this Groups meant for? Should it be the user instead

	return nil
}

// Permission is the struct representing the Civo permission
type Permission struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// returns the set of permissions the user has in the given account (it's the sum of the permissions for each team_membership)
// the information of the user is in the accessToken claims, meanwhile the account is taken from the configuration of the oauth-proxy
func (p *CivoProvider) getUserPermissionsInAccount(ctx context.Context, accessToken string) (permissions []Permission, err error) {

	// adding the account_id as query param for the request
	endpoint := fmt.Sprintf("%s%saccount_id=%s", p.PermissionsURL, joinerChar(p.PermissionsURL), p.Account)
	fmt.Printf("DEBUG - Civo: get permissions endpoint %s \n", endpoint)

	if err := requests.New(endpoint).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do().
		UnmarshalInto(&permissions); err != nil {
		return nil, err
	}

	return permissions, nil
}

func joinerChar(url string) string {
	if hasQueryParams(url) {
		return "&"
	}
	return "?"
}

// returns true if the current session returns a set of permissions having a match with the requiredPermissions
func (p *CivoProvider) isUserAllowed(userPermissions []Permission) bool {
	for _, perm := range userPermissions {
		if _, found := p.PermissionsMap[perm.Code]; found {
			return true
		}
	}
	fmt.Printf("DEBUG - Civo - isUserAllowed retuned false. User permissions %+v, Required one of these permissions %+v \n", userPermissions, p.PermissionsMap)
	return false
}
