// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"sync"

	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
)

// capturingCollector implements pApi.ComputeContextCollector in-plugin with
// TWO distinct pools that must not be confused:
//
//   - incomingEnvVars / incomingSecrets: the env vars the CONSUMER stack's
//     `uses:` resources contributed, delivered to this plugin's Provision
//     RPC via ProvisionRequest.compute_env_vars. The aws Lambda / ECS /
//     static-site drivers read these via EnvVariables() and
//     SecretEnvVariables() to inject them into their deployed containers
//     and function envs. Populated by newProvisionCollector; empty for
//     plain-resource Provision (s3-bucket, ecr-repository, etc.).
//
//   - outgoingEnvVars: what THIS plugin's compute processors
//     (RdsPostgres/RdsMysql/S3Bucket) added via AddEnvVariableIfNotExist /
//     AddSecretEnvVariableIfNotExist during a ComputeProcess RPC — the
//     mutations ToResponse() shapes into a ComputeProcessResponse the
//     plugin bus carries back to SC core, which then re-emits them on the
//     deploying stack's own compute context.
//
// Live-caught 2026-11-01 on forge-notifier staging deploy run 41336224941:
// the two pools used to be a SINGLE `envVars` plus an ECS-only
// `inputSecrets` with no non-secret incoming channel, and EnvVariables()
// returned nil ALWAYS. Lambda templates reading
// `params.ComputeContext.EnvVariables()` to pick up MONGO_USER /
// MONGO_PASSWORD from a parent mongodb cluster found nothing, so the
// Lambda env never gained those vars, the orphan SecretsManager secret
// got deleted, and the service went dark. See
// forge/docs/design/2026-11-01/plugin-extraction-playbook/ trap 14.
type capturingCollector struct {
	mu sync.Mutex

	// Incoming (from ProvisionRequest.compute_env_vars) — what the Lambda
	// / ECS / static-site driver reads to populate its deployed env.
	incomingEnvVars []pApi.ComputeEnvVariable
	incomingSecrets []pApi.ComputeEnvVariable

	// Outgoing (AddEnvVariableIfNotExist / AddSecretEnvVariableIfNotExist
	// mutations from THIS plugin's compute processors) — what
	// ToResponse() shapes into a ComputeProcessResponse.
	outgoingEnvVars []pApi.ComputeEnvVariable

	resourceTpl   []resourceTplEntry
	dependencyTpl []dependencyTplEntry
}

type resourceTplEntry struct {
	resName string
	values  map[string]string
}

type dependencyTplEntry struct {
	depName string
	resName string
	values  map[string]string
}

func newCapturingCollector() *capturingCollector {
	return &capturingCollector{}
}

// newProvisionCollector seeds the INCOMING pool from the ProvisionRequest's
// compute_env_vars so the Lambda / ECS / static-site driver's reads via
// EnvVariables() + SecretEnvVariables() return what the consumer stack's
// `uses:` resources contributed (MONGO_URI, MONGO_USER, MONGO_PASSWORD,
// bucket env, etc.).
//
// Unconditional for every cfg type: pre-fix this was gated on
// EcsFargateInput + ContainerSecrets, which silently dropped incoming
// env vars for aws-lambda, aws-static-website, and ECS stacks without
// container-secret declarations. Live-caught 2026-11-01 on forge-notifier
// — see the type-level doc.
func newProvisionCollector(req *scpluginv1.ProvisionRequest, _ any) *capturingCollector {
	c := newCapturingCollector()
	for _, v := range req.GetComputeEnvVars() {
		// Defensive: a nil entry or one with no name is a wire artefact
		// (unset proto field, protobuf's nil-safe getters would otherwise
		// synthesise an empty env var in the pool).
		if v == nil || v.GetName() == "" {
			continue
		}
		entry := pApi.ComputeEnvVariable{
			Name:         v.GetName(),
			Value:        v.GetValue(),
			Secret:       v.GetSecret(),
			ResourceName: v.GetResourceName(),
			ResourceType: v.GetResourceType(),
			StackName:    v.GetStackName(),
		}
		if v.GetSecret() {
			c.incomingSecrets = append(c.incomingSecrets, entry)
		} else {
			c.incomingEnvVars = append(c.incomingEnvVars, entry)
		}
	}
	return c
}

// EnvVariables returns the incoming (non-secret) compute env vars the
// deploying stack's `uses:` resources contributed. Lambda / ECS /
// static-site drivers read these to inject into the deployed container's
// environment.
func (c *capturingCollector) EnvVariables() []pApi.ComputeEnvVariable {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]pApi.ComputeEnvVariable(nil), c.incomingEnvVars...)
}

// SecretEnvVariables returns the incoming SECRET compute env vars. Same
// reader shape as EnvVariables(); the Secret flag is what drives the
// Lambda template to resolve the value via SecretsManager instead of
// baking it into the env directly.
func (c *capturingCollector) SecretEnvVariables() []pApi.ComputeEnvVariable {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]pApi.ComputeEnvVariable(nil), c.incomingSecrets...)
}

func (c *capturingCollector) AddEnvVariableIfNotExist(name, value, resType, resName, stackName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outgoingEnvVars = append(c.outgoingEnvVars, pApi.ComputeEnvVariable{
		Name: name, Value: value, ResourceType: resType, ResourceName: resName, StackName: stackName, Secret: false,
	})
}

func (c *capturingCollector) AddSecretEnvVariableIfNotExist(name, value, resType, resName, stackName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outgoingEnvVars = append(c.outgoingEnvVars, pApi.ComputeEnvVariable{
		Name: name, Value: value, ResourceType: resType, ResourceName: resName, StackName: stackName, Secret: true,
	})
}

func (c *capturingCollector) AddResourceTplExtension(resName string, values map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resourceTpl = append(c.resourceTpl, resourceTplEntry{resName: resName, values: values})
}

func (c *capturingCollector) AddDependencyTplExtension(depName, resName string, values map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dependencyTpl = append(c.dependencyTpl, dependencyTplEntry{depName: depName, resName: resName, values: values})
}

func (c *capturingCollector) AddDependency(sdk.Resource)                       {}
func (c *capturingCollector) Dependencies() []sdk.Resource                     { return nil }
func (c *capturingCollector) AddOutput(_ *sdk.Context, _ sdk.Output)           {}
func (c *capturingCollector) Outputs() []sdk.Output                            { return nil }
func (c *capturingCollector) ResolvePlaceholders(any) error                    { return nil }
func (c *capturingCollector) AddPreProcessor(any, pApi.PreProcessor)           {}
func (c *capturingCollector) AddPostProcessor(any, pApi.PostProcessor)         {}
func (c *capturingCollector) GetPreProcessors(any) ([]pApi.PreProcessor, bool) { return nil, false }

func (c *capturingCollector) GetPostProcessors(any) ([]pApi.PostProcessor, bool) { return nil, false }
func (c *capturingCollector) RunPreProcessors(any, any) error                    { return nil }
func (c *capturingCollector) RunPostProcessors(any, any) error                   { return nil }
func (c *capturingCollector) ResourceOutputs() pApi.ResourcesOutputs             { return nil }

// ToResponse packages the OUTGOING mutations (what THIS plugin's compute
// processors added) into a ComputeProcessResponse for the plugin bus.
// Does NOT echo back the incoming pool — those are context for THIS
// Provision, not something to re-send to SC core.
func (c *capturingCollector) ToResponse() *scpluginv1.ComputeProcessResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp := &scpluginv1.ComputeProcessResponse{}
	for _, v := range c.outgoingEnvVars {
		resp.EnvVars = append(resp.EnvVars, &scpluginv1.ComputeEnvVariable{
			Name:         v.Name,
			Value:        v.Value,
			Secret:       v.Secret,
			ResourceName: v.ResourceName,
			ResourceType: v.ResourceType,
			StackName:    v.StackName,
		})
	}
	for _, t := range c.resourceTpl {
		resp.TplExtensions = append(resp.TplExtensions, &scpluginv1.TemplateExtension{
			Kind:    scpluginv1.TemplateExtensionKind_TEMPLATE_EXTENSION_KIND_RESOURCE,
			ResName: t.resName,
			Values:  t.values,
		})
	}
	for _, t := range c.dependencyTpl {
		resp.TplExtensions = append(resp.TplExtensions, &scpluginv1.TemplateExtension{
			Kind:    scpluginv1.TemplateExtensionKind_TEMPLATE_EXTENSION_KIND_DEPENDENCY,
			DepName: t.depName,
			ResName: t.resName,
			Values:  t.values,
		})
	}
	return resp
}
