// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/simple-container-com/api/pkg/api"
)

func TestReadSesConfigurationSetConfig(t *testing.T) {
	RegisterTestingT(t)

	res, err := ReadSesConfigurationSetConfig(&api.Config{Config: map[string]any{
		"credentials":    "${auth:aws}",
		"account":        "645119433725",
		"region":         "eu-central-1",
		"name":           "mautic-events",
		"events":         []any{"BOUNCE", "COMPLAINT", "DELIVERY"},
		"httpsEndpoints": []any{"https://mautic.alphamind.co/mailer/callback"},
	}})
	Expect(err).ToNot(HaveOccurred())
	cfg, ok := res.Config.(*SesConfigurationSet)
	Expect(ok).To(BeTrue())
	Expect(cfg.Region).To(Equal("eu-central-1"))
	Expect(cfg.Account).To(Equal("645119433725"))
	Expect(cfg.CredentialsValue()).To(Equal("${auth:aws}"))
	Expect(cfg.Name).To(Equal("mautic-events"))
	Expect(cfg.EffectiveEvents()).To(Equal([]string{"BOUNCE", "COMPLAINT", "DELIVERY"}))
	Expect(cfg.HttpsEndpoints).To(Equal([]string{"https://mautic.alphamind.co/mailer/callback"}))
	Expect(cfg.Validate()).To(Succeed())
}

func TestSesConfigurationSetDefaults(t *testing.T) {
	RegisterTestingT(t)

	res, err := ReadSesConfigurationSetConfig(&api.Config{Config: map[string]any{"region": "eu-central-1"}})
	Expect(err).ToNot(HaveOccurred())
	cfg := res.Config.(*SesConfigurationSet)
	Expect(cfg.Validate()).To(Succeed(), "no endpoints and default events are valid")
	Expect(cfg.EffectiveEvents()).To(Equal([]string{"BOUNCE", "COMPLAINT"}))
	// The defaults are copied, never aliased.
	cfg.EffectiveEvents()[0] = "SEND"
	Expect(SesConfigurationSetDefaultEvents).To(Equal([]string{"BOUNCE", "COMPLAINT"}))
}

func TestSesConfigurationSetValidate(t *testing.T) {
	RegisterTestingT(t)

	Expect((&SesConfigurationSet{Events: SesEventTypes}).Validate()).To(Succeed())
	for _, ev := range []string{"bounce", "BOUNCES", "", "Complaint", "ALL"} {
		Expect((&SesConfigurationSet{Events: []string{"BOUNCE", ev}}).Validate()).
			To(MatchError(ContainSubstring("`events[1]`")), ev)
	}
	Expect((&SesConfigurationSet{Events: []string{"BOUNCE", "BOUNCE"}}).Validate()).To(MatchError(ContainSubstring("listed twice")))

	for _, ep := range []string{"https://mautic.alphamind.co/mailer/callback", "https://example.com:8443/hook?x=1"} {
		Expect((&SesConfigurationSet{HttpsEndpoints: []string{ep}}).Validate()).To(Succeed(), ep)
	}
	for _, ep := range []string{
		"http://mautic.alphamind.co/mailer/callback",
		"mautic.alphamind.co/mailer/callback",
		"https://",
		"https:///path",
		"https://user:pw@example.com/hook",
		"https://example.com/hook#frag",
		"",
		"HTTPS ://example.com",
	} {
		Expect((&SesConfigurationSet{HttpsEndpoints: []string{"https://ok.example.com", ep}}).Validate()).
			To(MatchError(ContainSubstring("`httpsEndpoints[1]`")), ep)
	}
	Expect((&SesConfigurationSet{HttpsEndpoints: []string{"https://a.example.com", "https://a.example.com"}}).Validate()).
		To(MatchError(ContainSubstring("listed twice")))
}

func TestValidateSesConfigurationSetName(t *testing.T) {
	RegisterTestingT(t)

	Expect(ValidateSesConfigurationSetName("mautic-ses-events", "mautic-ses-events--prod")).To(Succeed())
	for _, name := range []string{"mail_a", "mailA", "-mail", "mail-", ""} {
		Expect(ValidateSesConfigurationSetName(name, name+"--prod")).
			To(MatchError(ContainSubstring("lowercase letters, digits and hyphens")), name)
	}
	long := strings.Repeat("a", 60)
	Expect(ValidateSesConfigurationSetName(long, long+"--prod")).To(MatchError(ContainSubstring("longer than 64")))
}

func TestValidateSesConfigurationSetRegion(t *testing.T) {
	RegisterTestingT(t)

	Expect(ValidateSesConfigurationSetRegion("eu-central-1")).To(Succeed())
	Expect(ValidateSesConfigurationSetRegion("af-south-1")).To(MatchError(And(
		ContainSubstring(ResourceTypeSesConfigurationSet),
		ContainSubstring("has no Amazon SES SMTP endpoint"),
	)))
}
