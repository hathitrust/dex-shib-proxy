// Package authproxyshib implements a connector which relies on external
// authentication (e.g. mod_auth in Apache2) and returns an identity with
// claims populated with configurable header values.
//
// The primary use is to proxy a SAML SP running Shibboleth to OIDC
package authproxyshib

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds the configuration parameters for a connector which returns an
// identity with the HTTP header X-Remote-User as verified email.
type Config struct {
	UserIDHeader            string `json:"userIDHeader"`
	UsernameHeader          string `json:"usernameHeader"`
	PreferredUsernameHeader string `json:"preferredUsernameHeader"`
	EmailHeader             string `json:"emailHeader"`
	EmailVerifiedIfPresent  bool   `json:"emailVerifiedIfPresent"`
	GroupsHeader            string `json:"groupsHeader"`
	GroupsDelimiter         string `json:"groupsDelimiter"`
}

// Open returns an authentication strategy which requires no user interaction.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	userIDHeader := c.UserIDHeader
	if userIDHeader == "" {
		userIDHeader = "X-Remote-User"
	}

	groupsDelimiter := c.GroupsDelimiter
	if groupsDelimiter == "" {
		groupsDelimiter = ";"
	}

	return &callback{
		userIDHeader:            userIDHeader,
		usernameHeader:          c.UsernameHeader,
		preferredUsernameHeader: c.PreferredUsernameHeader,
		emailHeader:             c.EmailHeader,
		emailVerifiedIfPresent:  c.EmailVerifiedIfPresent,
		groupsHeader:            c.GroupsHeader,
		groupsDelimiter:         groupsDelimiter,
		logger:                  logger,
		pathSuffix:              "/" + id,
	}, nil
}

// Callback is a connector which returns an identity with the HTTP header
// X-Remote-User as verified email.
type callback struct {
	userIDHeader            string
	usernameHeader          string
	preferredUsernameHeader string
	emailHeader             string
	emailVerifiedIfPresent  bool
	groupsHeader            string
	groupsDelimiter         string
	logger                  log.Logger
	pathSuffix              string
}

// LoginURL returns the URL to redirect the user to login with.
func (m *callback) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	u.Path += m.pathSuffix
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

// HandleCallback parses the request and returns the user's identity
func (m *callback) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {
	m.logger.Debugf("Headers: %v", r.Header)
	userID := r.Header.Get(m.userIDHeader)
	if userID == "" {
		return connector.Identity{}, fmt.Errorf("required HTTP header %s is not set", m.userIDHeader)
	}

	identity := connector.Identity{
		UserID: userID,
	}

	if m.usernameHeader != "" {
		username := r.Header.Get(m.usernameHeader)
		if username != "" {
			identity.Username = username
		}
	}

	if m.preferredUsernameHeader != "" {
		preferredUsername := r.Header.Get(m.preferredUsernameHeader)
		if preferredUsername != "" {
			identity.PreferredUsername = preferredUsername
		}
	}

	if m.emailHeader != "" {
		email := r.Header.Get(m.emailHeader)
		if email != "" {
			identity.Email = email
			// TODO: what happens if missing from the config?
			identity.EmailVerified = m.emailVerifiedIfPresent
		}
	}

	if m.groupsHeader != "" {
		groups := r.Header.Get(m.groupsHeader)
		if groups != "" {
			identity.Groups = strings.Split(groups, m.groupsDelimiter)
		}
	}

	return identity, nil
}
