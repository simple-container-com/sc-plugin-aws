// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"regexp"
	"slices"
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
	// that use it (X-SES-CONFIGURATION-SET header, or ConfigurationSetName on
	// the API) are authorized - SES authorizes such a send against both the
	// identity and the configuration set ARN - and is exposed to consumers as
	// `configuration-set`. For a set created by aws-ses-configuration-set
	// this is its full name, `<name>--<env>`.
	ConfigurationSet string `json:"configurationSet,omitempty" yaml:"configurationSet,omitempty"`
	// FromAddresses, when set, restricts sends with a `ses:FromAddress`
	// StringLike condition (wildcards allowed, e.g. `*@example.com`).
	FromAddresses []string `json:"fromAddresses,omitempty" yaml:"fromAddresses,omitempty"`
	// APIAccess additionally allows the SES v2 API: ses:SendEmail on the same
	// resources and under the same conditions as ses:SendRawEmail, plus
	// ses:GetAccount (read-only, not resource-scoped; API clients use it for
	// the sending quota). The access key ID and secret are then also
	// exported as `access-key` and `secret-key`.
	APIAccess bool `json:"apiAccess,omitempty" yaml:"apiAccess,omitempty"`
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
		// IAM treats `*` and `?` in a resource ARN as patterns, so they
		// would grant sending as every matching (including future) identity.
		if strings.ContainsAny(id, "*?") {
			return errors.Errorf("%s: `identities[%d]` (%q) contains a wildcard (`*` or `?`); list each SES identity explicitly",
				ResourceTypeSesSmtpUser, i, id)
		}
	}
	// SES configuration set names allow only letters, digits, `-` and `_`;
	// in particular `*` / `?` would make the policy resource an IAM pattern.
	if c.ConfigurationSet != "" && !sesConfigurationSetNameRe.MatchString(c.ConfigurationSet) {
		return errors.Errorf("%s: `configurationSet` (%q) must be an SES configuration set name (letters, digits, `-` and `_`, at most %d characters)",
			ResourceTypeSesSmtpUser, c.ConfigurationSet, SesConfigurationSetNameMaxLen)
	}
	for i, from := range c.FromAddresses {
		if strings.TrimSpace(from) == "" {
			return errors.Errorf("%s: `fromAddresses[%d]` is empty", ResourceTypeSesSmtpUser, i)
		}
	}
	return nil
}

// SesSmtpRegions are the regions with an SES SMTP endpoint
// (email-smtp.<region>.amazonaws.com), per
// https://docs.aws.amazon.com/general/latest/gr/ses.html#ses_smtp_endpoints
// as of 2026-11. SES regions missing here (af-south-1, ap-south-2,
// ap-southeast-3, ap-southeast-5, ca-west-1, eu-central-2, eu-south-1,
// il-central-1, me-central-1, me-south-1, ...) have no SMTP endpoint.
var SesSmtpRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-south-1", "ap-southeast-1", "ap-southeast-2",
	"ca-central-1",
	"eu-central-1", "eu-north-1", "eu-west-1", "eu-west-2", "eu-west-3",
	"sa-east-1",
	"us-gov-east-1", "us-gov-west-1",
}

// ValidateSesSmtpRegion fails for a region without an SES SMTP endpoint.
func ValidateSesSmtpRegion(region string) error {
	return validateSesRegion(ResourceTypeSesSmtpUser, region)
}

// ValidateSesConfigurationSetRegion applies the aws-ses-smtp-user region
// allowlist to aws-ses-configuration-set, so a configuration set can always
// be used by an SMTP user in the same region.
func ValidateSesConfigurationSetRegion(region string) error {
	return validateSesRegion(ResourceTypeSesConfigurationSet, region)
}

func validateSesRegion(resourceType, region string) error {
	if !slices.Contains(SesSmtpRegions, region) {
		return errors.Errorf("%s: region %q has no Amazon SES SMTP endpoint; use one of %s (see https://docs.aws.amazon.com/general/latest/gr/ses.html#ses_smtp_endpoints)",
			resourceType, region, strings.Join(SesSmtpRegions, ", "))
	}
	return nil
}

var sesConfigurationSetNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var sesSmtpUserNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ValidateSesSmtpUserName requires lowercase letters, digits and hyphens in
// the resource name (or its `name` override). Consumers get the credentials
// as SMTP_<NAME>_* env vars, and SC upper-cases names and maps `-`/`_` (and
// camelCase) onto `_`; with this alphabet that mapping is one-to-one, so two
// resources a client uses can never share env var names (SC keeps the first
// value of a duplicate name and silently drops the rest).
func ValidateSesSmtpUserName(name string) error {
	if !sesSmtpUserNameRe.MatchString(name) {
		return errors.Errorf("%s: name %q must contain only lowercase letters, digits and hyphens (and start and end with a letter or digit), so its SMTP_<NAME>_* env vars cannot collide with another resource's",
			ResourceTypeSesSmtpUser, name)
	}
	return nil
}

func ReadSesSmtpUserConfig(config *api.Config) (api.Config, error) {
	return api.ConvertConfig(config, &SesSmtpUser{})
}
