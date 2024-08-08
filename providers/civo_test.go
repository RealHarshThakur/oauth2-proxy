package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testCivoProvider(hostname string) *CivoProvider {
	p := NewCivoProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""}, options.CivoOptions{})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
	}
	return p
}

func testCivoBackend(payload string) *httptest.Server {
	path := "/userinfo"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestNewCivoProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewCivoProvider(&ProviderData{}, options.CivoOptions{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("civo"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://auth.civo.com/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://auth.civo.com/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://auth.civo.com/userinfo"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://auth.civo.com/userinfo"))
	g.Expect(providerData.Scope).To(Equal("read"))
}

func TestCivoProviderOverrides(t *testing.T) {
	p := NewCivoProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			Scope: "profile"}, options.CivoOptions{})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "civo", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestCivoProviderGetEmailAddress(t *testing.T) {
	b := testCivoBackend(`{"email": "user@example.com"}`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCivoProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@example.com", email)
}

func TestCivoProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testCivoBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCivoProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestCivoProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testCivoBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCivoProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
