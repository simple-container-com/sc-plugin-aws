// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

// Package aws is the config tier of sc-plugin-aws. It owns every
// `aws` + `aws-*` + `s3-*` + `ecr-*` + `ecs-fargate` + `aws-lambda` +
// `aws-static-website` discriminator SC core parses out of a
// server.yaml, so that SC core can register the config decoders +
// template converters without pulling in pulumi-aws / pulumi-awsx.
//
// Extracted from pkg/clouds/aws in api as part of Phase 3+ per
// forge/docs/design/2026-10-24/sc-plugin-architecture/
// 07-plugin-first-for-new-clouds.md §8.
package aws

import (
	"github.com/simple-container-com/api/pkg/api"
)

func init() {
	api.RegisterProviderConfig(api.ConfigRegisterMap{
		// auth / secrets
		SecretsTypeAWSSecretsManager: ReadSecretsConfig,
		AuthTypeAWSToken:             ReadAuthServiceAccountConfig,

		// templates
		TemplateTypeEcsFargate:    ReadTemplateConfig,
		TemplateTypeAwsLambda:     ReadTemplateConfig,
		TemplateTypeStaticWebsite: ReadTemplateConfig,

		// bucket
		ResourceTypeS3Bucket: S3BucketReadConfig,

		// ecr
		ResourceTypeEcrRepository: EcrRepositoryReadConfig,

		// rds
		ResourceTypeRdsPostgres: ReadRdsPostgresConfig,
		ResourceTypeRdsMysql:    ReadRdsMysqlConfig,

		// security
		ResourceTypeCloudTrailSecurityAlerts: ReadCloudTrailSecurityAlertsConfig,
	})

	api.RegisterProvisionerFieldConfig(api.ProvisionerFieldConfigRegister{
		StateStorageTypeS3Bucket:  ReadStateStorageConfig,
		SecretsProviderTypeAwsKms: ReadSecretsProviderConfig,
	})

	api.RegisterCloudComposeConverter(api.CloudComposeConfigRegister{
		TemplateTypeEcsFargate: ToEcsFargateConfig,
	})

	api.RegisterCloudStaticSiteConverter(api.CloudStaticSiteConfigRegister{
		TemplateTypeStaticWebsite: ToStaticSiteConfig,
	})

	api.RegisterCloudSingleImageConverter(api.CloudSingleImageConfigRegister{
		TemplateTypeAwsLambda: ToAwsLambdaConfig,
	})

	// Fool-protection: SC core's parse-time ValidatePluginRequirements
	// auto-injects `plugins.aws:` with the latest release from GitHub
	// when it finds any owned token in a server.yaml without a
	// `plugins:` block. See api/pkg/api/plugin_requirements.go +
	// 04-no-destroy-invariant.md Addendum J.
	api.RegisterPluginRequirement(api.PluginRequirement{
		PluginName: "aws",
		OwnedTypes: []string{
			ProviderType,
			AuthTypeAWSToken,
			SecretsTypeAWSSecretsManager,
			StateStorageTypeS3Bucket,
			TemplateTypeEcsFargate,
			TemplateTypeAwsLambda,
			TemplateTypeStaticWebsite,
			ResourceTypeS3Bucket,
			ResourceTypeEcrRepository,
			ResourceTypeRdsPostgres,
			ResourceTypeRdsMysql,
			ResourceTypeCloudTrailSecurityAlerts,
			// aws-kms here is the Pulumi state-secrets-provider TYPE
			// (secretsProvider: {type: aws-kms, ...} on the stack
			// config) and its matching KMS-key provisioner — both move
			// with the plugin. The scoped-secrets per-value KMS
			// encryption in pkg/api/secrets/scoped/kms.go is a SEPARATE
			// surface: it keys on the awskms:// URL scheme in
			// scopes.yaml recipients (no "aws-kms" type discriminator)
			// and stays in SC core.
			SecretsProviderTypeAwsKms,
		},
		DefaultSource: api.PluginSource{
			Type:       "github-release",
			Repository: "simple-container-com/sc-plugin-aws",
		},
	})
}
