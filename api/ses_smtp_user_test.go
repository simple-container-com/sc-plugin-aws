// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/simple-container-com/api/pkg/api"
)

func TestReadSesSmtpUserConfig(t *testing.T) {
	RegisterTestingT(t)

	res, err := ReadSesSmtpUserConfig(&api.Config{Config: map[string]any{
		"credentials":      "${auth:aws}",
		"account":          "645119433725",
		"region":           "eu-central-1",
		"identities":       []any{"innmind.com"},
		"configurationSet": "mautic",
		"fromAddresses":    []any{"*@innmind.com"},
	}})
	Expect(err).ToNot(HaveOccurred())
	cfg, ok := res.Config.(*SesSmtpUser)
	Expect(ok).To(BeTrue())
	Expect(cfg.Region).To(Equal("eu-central-1"))
	Expect(cfg.Account).To(Equal("645119433725"))
	Expect(cfg.CredentialsValue()).To(Equal("${auth:aws}"))
	Expect(cfg.Identities).To(Equal([]string{"innmind.com"}))
	Expect(cfg.ConfigurationSet).To(Equal("mautic"))
	Expect(cfg.FromAddresses).To(Equal([]string{"*@innmind.com"}))
	Expect(cfg.Validate()).To(Succeed())
}

func TestSesSmtpUserValidate(t *testing.T) {
	RegisterTestingT(t)

	Expect((&SesSmtpUser{}).Validate()).To(MatchError(ContainSubstring("identities")))
	Expect((&SesSmtpUser{Identities: []string{" "}}).Validate()).To(MatchError(ContainSubstring("identities[0]")))
	Expect((&SesSmtpUser{Identities: []string{"innmind.com"}, FromAddresses: []string{""}}).Validate()).
		To(MatchError(ContainSubstring("fromAddresses[0]")))
	for _, id := range []string{"*", "*.innmind.com", "innmind.co?", "arn:aws:ses:eu-central-1:645119433725:identity/*", "arn:aws:ses:eu-central-1:*:identity/innmind.com"} {
		Expect((&SesSmtpUser{Identities: []string{"innmind.com", id}}).Validate()).
			To(MatchError(ContainSubstring("identities[1]")), id)
		Expect((&SesSmtpUser{Identities: []string{id}}).Validate()).To(MatchError(ContainSubstring("wildcard")), id)
	}
	Expect((&SesSmtpUser{Identities: []string{"innmind.com", "arn:aws:ses:eu-central-1:645119433725:identity/x.com"}}).Validate()).To(Succeed())
}

func TestValidateSesSmtpRegion(t *testing.T) {
	RegisterTestingT(t)

	for _, region := range []string{"eu-central-1", "us-east-1", "us-gov-west-1", "ap-northeast-3"} {
		Expect(ValidateSesSmtpRegion(region)).To(Succeed(), region)
	}
	// SES regions without an SMTP endpoint, plus non-SES / malformed values.
	for _, region := range []string{"af-south-1", "il-central-1", "eu-south-1", "ca-west-1", "me-south-1", "eu-central-3", "", "EU-CENTRAL-1"} {
		Expect(ValidateSesSmtpRegion(region)).To(MatchError(ContainSubstring("has no Amazon SES SMTP endpoint")), region)
	}
}

func TestValidateSesSmtpUserName(t *testing.T) {
	RegisterTestingT(t)

	for _, name := range []string{"mautic-ses", "mail-a", "a", "ses2"} {
		Expect(ValidateSesSmtpUserName(name)).To(Succeed(), name)
	}
	for _, name := range []string{"mail_a", "mailA", "MAIL-A", "-mail", "mail-", "mail.a", ""} {
		Expect(ValidateSesSmtpUserName(name)).To(MatchError(ContainSubstring("lowercase letters, digits and hyphens")), name)
	}
}
