// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"github.com/pkg/errors"
	"github.com/simple-container-com/api/pkg/api"
)

const TemplateTypeStaticWebsite = "aws-static-website"

type StaticSiteInput struct {
	TemplateConfig        `json:"templateConfig" yaml:"templateConfig"`
	api.StackConfigStatic `json:",inline" yaml:",inline"`
	StackDir              string `json:"stackDir" yaml:"stackDir"`
	StackName             string `json:"stackName" yaml:"stackName"`

	// Top-level mirrors of StackConfigStatic.Site fields. SC core's
	// JSON marshal drops the `Site` subtree because `Site` is a NAMED
	// field with `json:",inline"` (trap 6 of the plugin extraction
	// playbook). Plugins that read `cfg.Site.X` directly off the wire
	// find X empty — live-caught 2026-11-02 on landing's forge-landing
	// deploy run 41409219496 after the SC CLI image floated to a
	// newer release and masked a latent defect.
	//
	// `ToStaticSiteConfig` populates these; the driver reads them with
	// a Site.* fallback via the EffectiveX accessors below. Clients
	// NEVER author these fields.
	SiteDomain             string `json:"siteDomain,omitempty" yaml:"siteDomain,omitempty"`
	SiteBaseDnsZone        string `json:"siteBaseDnsZone,omitempty" yaml:"siteBaseDnsZone,omitempty"`
	SiteIndexDocument      string `json:"siteIndexDocument,omitempty" yaml:"siteIndexDocument,omitempty"`
	SiteErrorDocument      string `json:"siteErrorDocument,omitempty" yaml:"siteErrorDocument,omitempty"`
	SiteProvisionWwwDomain *bool  `json:"siteProvisionWwwDomain,omitempty" yaml:"siteProvisionWwwDomain,omitempty"`
}

// EffectiveDomain returns the resolved apex hostname, preferring the
// top-level SiteDomain mirror over Site.Domain (trap 6 drops the
// latter on the SC-core → plugin JSON marshal).
func (i *StaticSiteInput) EffectiveDomain() string {
	if i.SiteDomain != "" {
		return i.SiteDomain
	}
	return i.Site.Domain
}

// EffectiveBaseDnsZone returns the resolved DNS zone, preferring the
// top-level SiteBaseDnsZone mirror over Site.BaseDnsZone.
func (i *StaticSiteInput) EffectiveBaseDnsZone() string {
	if i.SiteBaseDnsZone != "" {
		return i.SiteBaseDnsZone
	}
	return i.Site.BaseDnsZone
}

// EffectiveIndexDocument returns the resolved index page, preferring
// the top-level SiteIndexDocument mirror over Site.IndexDocument.
func (i *StaticSiteInput) EffectiveIndexDocument() string {
	if i.SiteIndexDocument != "" {
		return i.SiteIndexDocument
	}
	return i.Site.IndexDocument
}

// EffectiveErrorDocument returns the resolved error page, preferring
// the top-level SiteErrorDocument mirror over Site.ErrorDocument.
func (i *StaticSiteInput) EffectiveErrorDocument() string {
	if i.SiteErrorDocument != "" {
		return i.SiteErrorDocument
	}
	return i.Site.ErrorDocument
}

// EffectiveProvisionWwwDomain returns the resolved provisionWwwDomain
// bool, preferring the top-level SiteProvisionWwwDomain mirror.
func (i *StaticSiteInput) EffectiveProvisionWwwDomain() bool {
	if i.SiteProvisionWwwDomain != nil {
		return *i.SiteProvisionWwwDomain
	}
	return i.Site.ProvisionWwwDomain
}

// OverriddenBaseZone implements api.DnsConfigAware so the Cloudflare registrar
// uses the stack's baseDnsZone instead of the parent stack's default zone —
// otherwise records get created with the parent zone suffixed (e.g.
// simple-forge.com → simple-forge.com.simple-container.com).
func (i *StaticSiteInput) OverriddenBaseZone() string {
	return i.EffectiveBaseDnsZone()
}

func ToStaticSiteConfig(tpl any, stackDir, stackName string, stackCfg *api.StackConfigStatic) (any, error) {
	templateCfg, ok := tpl.(*TemplateConfig)
	if !ok {
		return nil, errors.Errorf("template config is not of type aws.TemplateConfig")
	}

	if templateCfg == nil {
		return nil, errors.Errorf("template config is nil")
	}

	if stackCfg == nil {
		return nil, errors.Errorf("stack config is nil")
	}

	accountConfig := &AccountConfig{}
	err := api.ConvertAuth(&templateCfg.AccountConfig, accountConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert aws account config")
	}
	templateCfg.AccountConfig = *accountConfig

	// Populate top-level mirrors so trap 6 (SC-core JSON marshal drops the
	// named `Site` field with `json:",inline"`) does not leave the plugin
	// side reading cfg.Site.X as empty. See the StaticSiteInput doc for
	// context and landing deploy run 41409219496 (2026-11-02) for the
	// live-caught failure.
	provisionWww := stackCfg.Site.ProvisionWwwDomain
	res := &StaticSiteInput{
		TemplateConfig:         *templateCfg,
		StackConfigStatic:      *stackCfg,
		StackDir:               stackDir,
		StackName:              stackName,
		SiteDomain:             stackCfg.Site.Domain,
		SiteBaseDnsZone:        stackCfg.Site.BaseDnsZone,
		SiteIndexDocument:      stackCfg.Site.IndexDocument,
		SiteErrorDocument:      stackCfg.Site.ErrorDocument,
		SiteProvisionWwwDomain: &provisionWww,
	}

	return res, nil
}
