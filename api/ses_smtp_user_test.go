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
	Expect((&SesSmtpUser{Identities: []string{"innmind.com", "arn:aws:ses:eu-central-1:645119433725:identity/x.com"}}).Validate()).To(Succeed())
}
