package tower_caddy_auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(TowerAuth{})
	httpcaddyfile.RegisterHandlerDirective("tower_auth", parseCaddyfile)
}

// TowerAuth is a Caddy HTTP middleware that enforces authentication via a
// centralised auth server. It implements a proxy-driven SSO pattern:
//
//  1. If the request carries ?token=<one-time-token>, it exchanges the token
//     with the auth server, sets a session cookie, then redirects to the same
//     URL without the token (so the token never lingers in browser history).
//
//  2. If the request carries the session cookie, it validates the session with
//     the auth server and injects the returned identity headers (X-User, etc.)
//     before proxying to the upstream.
//
//  3. Otherwise it redirects the browser to the auth server login page.
//
//  4. Requests to LogoutPath are handled by invalidating the session on the
//     auth server and clearing the cookie.
type TowerAuth struct {
	// AuthServerURL is the base URL of the auth server (required).
	// Example: http://tower-auth:3000
	AuthServerURL string `json:"auth_server_url"`

	// CookieName is the name of the per-app session cookie.
	// Defaults to "tower_auth".
	CookieName string `json:"cookie_name,omitempty"`

	// LogoutPath is the request path that triggers logout handling.
	// Defaults to "/logout".
	LogoutPath string `json:"logout_path,omitempty"`

	client *http.Client
}

// CaddyModule returns the Caddy module information.
func (TowerAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tower_auth",
		New: func() caddy.Module { return new(TowerAuth) },
	}
}

// Provision sets defaults and initialises the HTTP client.
func (m *TowerAuth) Provision(_ caddy.Context) error {
	if m.CookieName == "" {
		m.CookieName = "tower_auth"
	}
	if m.LogoutPath == "" {
		m.LogoutPath = "/logout"
	}
	m.client = &http.Client{}
	return nil
}

// Validate checks required configuration.
func (m *TowerAuth) Validate() error {
	if m.AuthServerURL == "" {
		return fmt.Errorf("tower_auth: auth_server is required")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m TowerAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.URL.Path == m.LogoutPath {
		return m.handleLogout(w, r)
	}

	if token := r.URL.Query().Get("token"); token != "" {
		return m.handleTokenExchange(w, r, token)
	}

	if cookie, err := r.Cookie(m.CookieName); err == nil {
		return m.handleSessionCheck(w, r, next, cookie.Value)
	}

	return m.redirectToLogin(w, r)
}

// exchangeResponse is the JSON body returned by POST /exchange.
type exchangeResponse struct {
	Session string            `json:"session"`
	User    string            `json:"user"`
	Email   string            `json:"email"`
	Headers map[string]string `json:"headers,omitempty"`
}

// handleTokenExchange exchanges a one-time login token for a session cookie,
// then redirects the browser to the same URL without the token query param.
func (m TowerAuth) handleTokenExchange(w http.ResponseWriter, r *http.Request, token string) error {
	resp, err := m.client.PostForm(m.AuthServerURL+"/exchange", url.Values{"token": {token}})
	if err != nil {
		return fmt.Errorf("tower_auth: token exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Bad / expired token - send the user back to login.
		return m.redirectToLogin(w, r)
	}

	var data exchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("tower_auth: decode exchange response: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    data.Session,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to strip ?token from the URL so it does not appear in browser
	// history, bookmarks, or Referer headers.
	http.Redirect(w, r, withoutToken(r.URL), http.StatusFound)
	return nil
}

// handleSessionCheck validates the session cookie against the auth server.
// On success it injects the identity headers returned by the auth server and
// calls the next handler. On failure it clears the stale cookie and redirects.
func (m TowerAuth) handleSessionCheck(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, sessionID string) error {
	req, err := http.NewRequest(http.MethodGet, m.AuthServerURL+"/check", nil)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{Name: m.CookieName, Value: sessionID})

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("tower_auth: session check request: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body) }() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		clearCookie(w, m.CookieName)
		return m.redirectToLogin(w, r)
	}

	// Inject identity headers from the auth server into the upstream request.
	// Any pre-existing headers with the same names are replaced to prevent
	// clients from spoofing identity.
	for key, values := range resp.Header {
		if strings.HasPrefix(strings.ToUpper(key), "X-") {
			r.Header.Del(key)
			for _, v := range values {
				r.Header.Add(key, v)
			}
		}
	}

	return next.ServeHTTP(w, r)
}

// handleLogout invalidates the session on the auth server, clears the cookie,
// and redirects the browser to the auth server home page.
func (m TowerAuth) handleLogout(w http.ResponseWriter, r *http.Request) error {
	if cookie, err := r.Cookie(m.CookieName); err == nil {
		req, _ := http.NewRequest(http.MethodPost, m.AuthServerURL+"/logout", nil)
		req.AddCookie(&http.Cookie{Name: m.CookieName, Value: cookie.Value})
		resp, err := m.client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	}
	clearCookie(w, m.CookieName)
	http.Redirect(w, r, m.AuthServerURL, http.StatusFound)
	return nil
}

// redirectToLogin sends the browser to the auth server login page, passing the
// current URL as the return destination.
func (m TowerAuth) redirectToLogin(w http.ResponseWriter, r *http.Request) error {
	loginURL := m.AuthServerURL + "/login?return=" + url.QueryEscape(fullURL(r))
	http.Redirect(w, r, loginURL, http.StatusFound)
	return nil
}

// --- helpers -----------------------------------------------------------------

// fullURL reconstructs the full request URL including scheme and host.
func fullURL(r *http.Request) string {
	u := *r.URL
	u.Host = r.Host
	if u.Scheme == "" {
		if r.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	return u.String()
}

// withoutToken returns the request URL as a string with the ?token parameter
// removed (preserving all other query parameters).
func withoutToken(u *url.URL) string {
	q := u.Query()
	q.Del("token")
	out := *u
	out.RawQuery = q.Encode()
	return out.String()
}

// clearCookie writes a Set-Cookie header that immediately expires the named
// cookie.
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- Caddyfile parsing -------------------------------------------------------

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m TowerAuth
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

// UnmarshalCaddyfile parses the tower_auth directive:
//
//	tower_auth {
//	    auth_server <url>
//	    cookie_name <name>   # optional, default: tower_auth
//	    logout_path <path>   # optional, default: /logout
//	}
func (m *TowerAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	for d.NextBlock(0) {
		switch d.Val() {
		case "auth_server":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.AuthServerURL = d.Val()
		case "cookie_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CookieName = d.Val()
		case "logout_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.LogoutPath = d.Val()
		default:
			return d.Errf("unknown tower_auth subdirective: %q", d.Val())
		}
	}
	return nil
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*TowerAuth)(nil)
	_ caddy.Validator             = (*TowerAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*TowerAuth)(nil)
	_ caddyfile.Unmarshaler       = (*TowerAuth)(nil)
)
