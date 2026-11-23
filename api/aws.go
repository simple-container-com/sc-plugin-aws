// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import "github.com/simple-container-com/api/pkg/api"

// ProviderType is the top-level discriminator every AWS config reports
// from ProviderType(). Lives here (not init.go) so a build that pulled
// in just this one package still compiles.
const ProviderType = "aws"

type TemplateConfig struct {
	AccountConfig `json:",inline" yaml:",inline"`
}

type (
	LambdaRoutingType string
	LambdaInvokeMode  string
	LoadBalancerType  string
)

const (
	LambdaRoutingApiGw             = "api-gateway"
	LambdaRoutingFunctionUrl       = "function-url"
	LambdaInvokeModeBuffered       = "BUFFERED"
	LambdaInvokeModeResponseStream = "RESPONSE_STREAM"

	LoadBalancerTypeAlb LoadBalancerType = "alb"
	LoadBalancerTypeNlb LoadBalancerType = "nlb"
)

type CloudExtras struct {
	// ContainerSecrets restricts ECS secret injection by compose service name.
	// A missing service inherits all stack/context secrets; an empty list gets none.
	ContainerSecrets map[string][]string `json:"containerSecrets,omitempty" yaml:"containerSecrets,omitempty"`

	// All hardening flags default to false to preserve existing stacks.
	LeastPrivilegeRoles             bool `json:"leastPrivilegeRoles,omitempty" yaml:"leastPrivilegeRoles,omitempty"`
	RestrictTaskIngress             bool `json:"restrictTaskIngress,omitempty" yaml:"restrictTaskIngress,omitempty"`
	NlbSecurityGroups               bool `json:"nlbSecurityGroups,omitempty" yaml:"nlbSecurityGroups,omitempty"`
	EnableHTTPS                     bool `json:"enableHTTPS,omitempty" yaml:"enableHTTPS,omitempty"`
	DisablePublicIPWithStaticEgress bool `json:"disablePublicIPWithStaticEgress,omitempty" yaml:"disablePublicIPWithStaticEgress,omitempty"`

	AwsRoles          []string          `json:"awsRoles" yaml:"awsRoles"`
	LambdaSchedule    *LambdaSchedule   `json:"lambdaSchedule,omitempty" yaml:"lambdaSchedule,omitempty"`   // e.g. for lambda functions to be triggered on schedule
	LambdaSchedules   []LambdaSchedule  `json:"lambdaSchedules,omitempty" yaml:"lambdaSchedules,omitempty"` // e.g. for lambda functions to be triggered on schedule
	LambdaRoutingType LambdaRoutingType `json:"lambdaRoutingType" yaml:"lambdaRoutingType"`
	LambdaInvokeMode  LambdaInvokeMode  `json:"lambdaInvokeMode" yaml:"lambdaInvokeMode"` // invoke mode for lambda

	// Concurrency controls for aws-lambda. Both are opt-in; both nil keeps
	// the template bit-identical to pre-knob deploys (AWS unreserved,
	// $LATEST targeted by the Function URL / API Gateway).
	//
	// ReservedConcurrency caps simultaneous executions of this function at
	// `*ReservedConcurrency` (maps to lambda.Function.ReservedConcurrentExecutions).
	//
	//   - nil → unreserved (AWS default: shares the account-wide pool).
	//   - 0   → DISABLE the function (AWS returns throttle errors for every
	//     invocation). Useful as a kill-switch; still set here deliberately,
	//     not by accident.
	//   - ≥1  → hard cap.
	//
	// No cost on its own — this is a scheduler hint, not provisioned
	// capacity. Use it to protect downstream services from a stampede or
	// to bound the account-pool share this function consumes.
	//
	// ProvisionedConcurrency keeps `*ProvisionedConcurrency` warm containers
	// permanently alive so predictable load does not pay cold-start latency.
	//
	//   - nil → no provisioning (every invocation may cold-start).
	//   - ≥1  → that many warm containers kept hot. Requires a published
	//     Lambda version + alias; the plugin creates both automatically,
	//     and re-targets the Function URL / API Gateway integration at the
	//     alias. Zero is rejected (use nil instead).
	//
	// Costs money even when idle — AWS bills provisioned concurrency
	// per container-GB-second (~$0.015/GB-hour us-east-1). Reach for it
	// when cold-start p99 is the fleet pain point, not as a default.
	//
	// When both are set, `ReservedConcurrency` must be ≥ `ProvisionedConcurrency`
	// (AWS requires the reserved pool to accommodate the warm fleet). The
	// template does not enforce this at parse time — AWS validates it when
	// the ProvisionedConcurrencyConfig is created and the deploy fails
	// loudly with the offending pair.
	ReservedConcurrency    *int `json:"reservedConcurrency,omitempty" yaml:"reservedConcurrency,omitempty"`
	ProvisionedConcurrency *int `json:"provisionedConcurrency,omitempty" yaml:"provisionedConcurrency,omitempty"`

	SecurityGroup    *SecurityGroup   `json:"securityGroup,omitempty" yaml:"securityGroup,omitempty"`
	LoadBalancerType LoadBalancerType `json:"loadBalancerType,omitempty" yaml:"loadBalancerType,omitempty"` // default: alb

	// SecretsBundle — opt-in secrets consolidation (design 2026-10-17,
	// `forge/docs/design/2026-10-17/sc-secrets-bundle-mode/`). When
	// non-nil, SC renders ONE AWS Secrets Manager secret per service
	// with a JSON payload of `{envName:string → value:string}` plus ONE
	// env var `FORGE_SECRETS_BUNDLE_ARN` pointing at it, instead of N
	// per-key secrets each occupying a Lambda env slot. nil = legacy
	// per-key byte-for-byte. See `SecretsBundleConfig` for the fields;
	// `secretsBundle: {}` in YAML is the minimal opt-in (defaults
	// enabled). Mirrors the pointer-struct pattern k8s.VPA uses.
	SecretsBundle *SecretsBundleConfig `json:"secretsBundle,omitempty" yaml:"secretsBundle,omitempty"`

	// RollingUpdate overrides the ECS service deploymentConfiguration of an
	// ecs-fargate cloud-compose stack. nil (or an unset field) keeps the
	// defaults minimumHealthyPercent 100 / maximumPercent 200. See
	// EcsRollingUpdate.
	RollingUpdate *EcsRollingUpdate `json:"rollingUpdate,omitempty" yaml:"rollingUpdate,omitempty"`
}

// SecretsBundleConfig configures the opt-in Secrets Manager bundling
// mode. All fields are optional; the zero value of the struct (any
// non-nil SecretsBundle with no fields set) enables bundle rendering
// with sensible defaults.
type SecretsBundleConfig struct {
	// Enabled defaults to true when SecretsBundle is non-nil. The
	// explicit `enabled: false` form is accepted so the operator can
	// stage a rollback without removing the whole block (keeps git
	// diffs small). nil pointer = treated as true.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// Name — optional secret-name suffix override. Default naming is
	// `<stack>--<env>--secrets-bundle--v1` (sibling of the per-key
	// naming scheme in `plugin/internal/secrets.go:20`).
	// Operators who need a human-readable alias can set this.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// MaxEntries — optional guard against runaway `env:` growth
	// outpacing the 65 KB Secrets Manager payload cap. Zero = no
	// check; Pulumi preflight rejects renders over this count.
	MaxEntries int `json:"maxEntries,omitempty" yaml:"maxEntries,omitempty"`

	// KMSKeyID — optional CMK for encrypting the bundle secret.
	// Default is the AWS-managed `aws/secretsmanager` key.
	KMSKeyID string `json:"kmsKeyId,omitempty" yaml:"kmsKeyId,omitempty"`
}

// IsEnabled reports whether the bundle is on. nil receiver → false
// (legacy per-key rendering). Non-nil with Enabled unset → true (the
// minimal `secretsBundle: {}` form opts in). Non-nil with Enabled=false
// → false (operator-staged rollback escape hatch).
func (b *SecretsBundleConfig) IsEnabled() bool {
	if b == nil {
		return false
	}
	if b.Enabled == nil {
		return true
	}
	return *b.Enabled
}

type SecurityGroup struct {
	Ingress *SecurityGroupRule `json:"ingress,omitempty" yaml:"ingress,omitempty"`
}

type SecurityGroupRule struct {
	AllowOnlyCloudflare *bool     `json:"allowOnlyCloudflare,omitempty" yaml:"allowOnlyCloudflare,omitempty"`
	CidrBlocks          *[]string `json:"cidrBlocks,omitempty" yaml:"cidrBlocks,omitempty"`
	Ipv6CidrBlocks      *[]string `json:"ipv6CidrBlocks,omitempty" yaml:"ipv6CidrBlocks,omitempty"`
}

func ReadTemplateConfig(config *api.Config) (api.Config, error) {
	return api.ConvertConfig(config, &TemplateConfig{})
}
