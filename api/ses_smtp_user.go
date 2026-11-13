// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"strings"

	"github.com/pkg/errors"

	"github.com/simple-container-com/api/pkg/api"
)

const ResourceTypeSesSmtpUser = "aws-ses-smtp-user"

// SesSmtpUserDefaultPort is the SES SMTP STARTTLS port handed to consumers.
const SesSmtpUserDefaultPort = 587

// SesSmtpUser provisions Amazon SES SMTP credentials: a dedicated IAM user,
// an inline policy allowing only ses:SendRawEmail (the single action the
// SES SMTP interface needs) on the configured identities, and an access key
// whose SigV4-derived SMTP password is exported as a secret.
//
// The SES identities themselves (domain verification, DKIM, MAIL FROM) are
// managed out of band; this resource only references them.
//
// `region` (from the embedded AccountConfig) is the SES region the SMTP
// endpoint and the SMTP password are bound to. When omitted, the region of
// the `${auth:...}` credentials is used.
type SesSmtpUser struct {
	AccountConfig `json:",inline" yaml:",inline"`
	// Name overrides the base name of the IAM resources (defaults to the
	// resource name in server.yaml).
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Identities are SES identities the user may send from: verified domains
	// (`example.com`), email addresses (`noreply@example.com`) or full SES
	// identity ARNs. Required.
	Identities []string `json:"identities" yaml:"identities"`
	// ConfigurationSet, when set, is added to the policy resources so sends
	// that use it (X-SES-CONFIGURATION-SET header) are authorized, and is
	// exposed to consumers as `configuration-set`.
	ConfigurationSet string `json:"configurationSet,omitempty" yaml:"configurationSet,omitempty"`
	// FromAddresses, when set, restricts sends with a `ses:FromAddress`
	// StringLike condition (wildcards allowed, e.g. `*@example.com`).
	FromAddresses []string `json:"fromAddresses,omitempty" yaml:"fromAddresses,omitempty"`
}

// Validate checks the fields the plugin cannot default.
func (c *SesSmtpUser) Validate() error {
	if len(c.Identities) == 0 {
		return errors.Errorf("%s: `identities` must list at least one SES identity", ResourceTypeSesSmtpUser)
	}
	for i, id := range c.Identities {
		if strings.TrimSpace(id) == "" {
			return errors.Errorf("%s: `identities[%d]` is empty", ResourceTypeSesSmtpUser, i)
		}
	}
	for i, from := range c.FromAddresses {
		if strings.TrimSpace(from) == "" {
			return errors.Errorf("%s: `fromAddresses[%d]` is empty", ResourceTypeSesSmtpUser, i)
		}
	}
	return nil
}

func ReadSesSmtpUserConfig(config *api.Config) (api.Config, error) {
	return api.ConvertConfig(config, &SesSmtpUser{})
}
