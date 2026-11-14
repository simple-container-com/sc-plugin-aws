// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"net/url"
	"slices"
	"strings"

	"github.com/pkg/errors"

	"github.com/simple-container-com/api/pkg/api"
)

const ResourceTypeSesConfigurationSet = "aws-ses-configuration-set"

// SesConfigurationSetDefaultEvents are the SES event types published when
// `events` is omitted: the ones a sender must act on to keep its reputation.
var SesConfigurationSetDefaultEvents = []string{"BOUNCE", "COMPLAINT"}

// SesEventTypes are the SES v2 event types an event destination can match,
// per https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_EventDestination.html
var SesEventTypes = []string{
	"SEND", "REJECT", "BOUNCE", "COMPLAINT", "DELIVERY", "OPEN", "CLICK",
	"RENDERING_FAILURE", "DELIVERY_DELAY", "SUBSCRIPTION",
}

// SesConfigurationSetNameMaxLen is SES's limit on a configuration set name.
const SesConfigurationSetNameMaxLen = 64

// SesConfigurationSet provisions an SES v2 configuration set whose sending
// events are published to a dedicated SNS topic, optionally fanned out to
// HTTPS endpoints (e.g. a mailer's bounce/complaint webhook).
//
// The SES configuration set is named `<name>--<env>` (the same env-suffixed
// name SC gives every resource), where `<name>` is `name` or the resource
// name. An aws-ses-smtp-user sending through it references that exact name
// in its `configurationSet`.
//
// `region` (from the embedded AccountConfig) is the SES region; when omitted,
// the region of the `${auth:...}` credentials is used. It must be a region
// with an SES SMTP endpoint, like aws-ses-smtp-user's, so the two resources
// can always be paired.
type SesConfigurationSet struct {
	AccountConfig `json:",inline" yaml:",inline"`
	// Name overrides the base name (defaults to the resource name in
	// server.yaml). The SES configuration set is named `<name>--<env>`.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Events are the SES event types published to the SNS topic. Defaults
	// to SesConfigurationSetDefaultEvents.
	Events []string `json:"events,omitempty" yaml:"events,omitempty"`
	// HttpsEndpoints are subscribed to the SNS topic with the `https`
	// protocol. Each endpoint must confirm the subscription itself (SNS
	// POSTs a SubscriptionConfirmation with a SubscribeURL). May be empty.
	HttpsEndpoints []string `json:"httpsEndpoints,omitempty" yaml:"httpsEndpoints,omitempty"`
}

// EffectiveEvents returns the configured events, or the defaults.
func (c *SesConfigurationSet) EffectiveEvents() []string {
	if len(c.Events) == 0 {
		return slices.Clone(SesConfigurationSetDefaultEvents)
	}
	return c.Events
}

// Validate checks the fields the plugin cannot default.
func (c *SesConfigurationSet) Validate() error {
	seen := map[string]bool{}
	for i, ev := range c.Events {
		if !slices.Contains(SesEventTypes, ev) {
			return errors.Errorf("%s: `events[%d]` (%q) is not an SES event type; use one of %s",
				ResourceTypeSesConfigurationSet, i, ev, strings.Join(SesEventTypes, ", "))
		}
		if seen[ev] {
			return errors.Errorf("%s: `events[%d]` (%q) is listed twice", ResourceTypeSesConfigurationSet, i, ev)
		}
		seen[ev] = true
	}
	seen = map[string]bool{}
	for i, endpoint := range c.HttpsEndpoints {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.Errorf("%s: `httpsEndpoints[%d]` (%q) must be an absolute https:// URL without credentials or fragment",
				ResourceTypeSesConfigurationSet, i, endpoint)
		}
		if seen[endpoint] {
			return errors.Errorf("%s: `httpsEndpoints[%d]` (%q) is listed twice", ResourceTypeSesConfigurationSet, i, endpoint)
		}
		seen[endpoint] = true
	}
	return nil
}

// ValidateSesConfigurationSetName checks the base name (resource name or
// `name`) and the resulting SES configuration set name. The base name uses
// the same alphabet as aws-ses-smtp-user, so the SES_<NAME>_* env vars of two
// resources can never collide; the full name must fit SES's 64 characters.
func ValidateSesConfigurationSetName(baseName, sesName string) error {
	if !sesSmtpUserNameRe.MatchString(baseName) {
		return errors.Errorf("%s: name %q must contain only lowercase letters, digits and hyphens (and start and end with a letter or digit), so its SES_<NAME>_* env vars cannot collide with another resource's",
			ResourceTypeSesConfigurationSet, baseName)
	}
	if len(sesName) > SesConfigurationSetNameMaxLen {
		return errors.Errorf("%s: configuration set name %q is longer than %d characters; shorten the resource name or set a shorter `name`",
			ResourceTypeSesConfigurationSet, sesName, SesConfigurationSetNameMaxLen)
	}
	return nil
}

func ReadSesConfigurationSetConfig(config *api.Config) (api.Config, error) {
	return api.ConvertConfig(config, &SesConfigurationSet{})
}
