// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

// sc-plugin-aws is the Simple Container plugin for AWS, extracted from
// `pkg/clouds/{aws,pulumi/aws}` per Phase 3+ of
// forge/docs/design/2026-10-24/sc-plugin-architecture/
// 07-plugin-first-for-new-clouds.md §8.
//
// # Shipped scope (v1)
//
//   - AWS Pulumi provider (`aws:index/provider:Provider`).
//   - Resources: `s3-bucket`, `ecr-repository`, `aws-rds-postgres`,
//     `aws-rds-mysql`, `aws-cloudtrail-security-alerts`.
//   - Templates: `ecs-fargate`, `aws-lambda`, `aws-static-website`.
//   - State backend: `s3-bucket` (via the `aws-token` auth block).
//   - Pulumi stack-secrets provider: `aws-kms` (KMS key resource +
//     provider wiring).
//   - ComputeProcessors for `s3-bucket`, `aws-rds-postgres`,
//     `aws-rds-mysql`. The RDS pair reads the parent-stack
//     endpoint/port/root creds and emits `<PREFIX>_HOST / _PORT /
//     _USER / _PASSWORD / _URI / _DB` env vars + resource tpl
//     extensions. S3 emits bucket name + arn + region.
//   - PreDestroy is a scaffolding stub — no in-tree AWS code consumed
//     the pre-destroy hook today.
//
// # Separate: `cloud-helpers` Lambda
//
// The CloudWatch alert + health-event handler binary ships in
// `cmd/cloud-helpers/` of this repo and imports
// `plugin/internal/helpers` only (no pulumi-aws). Keeping those two
// binaries co-located means operators can bump the Lambda handler and
// the SC-core-facing config decoder in a single release.
//
// # Not yet shipped
//
//   - PeerInvoke exposure of `LookupSubnetsInAccount` +
//     `NewVpcInAccount` so sc-plugin-mongodb v2 can broker a
//     SecurityGroup + VpcEndpoint for PrivateLink. Blocked on the
//     `SCCore.PeerInvoke` callback RPC — only the plugin-side
//     `BrokerAware` scaffold has shipped (api #509).
package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/pkg/errors"

	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/simple-container-com/api/pkg/api"
	"github.com/simple-container-com/api/pkg/api/logger"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	scPlugin "github.com/simple-container-com/api/pkg/plugin"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
	awsApi "github.com/simple-container-com/sc-plugin-aws/api"
	awsInternal "github.com/simple-container-com/sc-plugin-aws/plugin/internal"
)

type awsPlugin struct {
	scpluginv1.UnimplementedSCCloudPluginServer

	mu       sync.Mutex
	progress *scPlugin.Publisher
}

func (p *awsPlugin) Schema(_ context.Context, _ *scpluginv1.SchemaRequest) (*scpluginv1.SchemaResponse, error) {
	return &scpluginv1.SchemaResponse{
		PluginVersion: "aws-0.0.1",
		ProviderTypes: []string{awsApi.ProviderType},
		ResourceTypes: []string{
			awsApi.ResourceTypeS3Bucket,
			awsApi.ResourceTypeEcrRepository,
			awsApi.ResourceTypeRdsPostgres,
			awsApi.ResourceTypeRdsMysql,
			awsApi.ResourceTypeCloudTrailSecurityAlerts,
			awsApi.TemplateTypeEcsFargate,
			awsApi.TemplateTypeAwsLambda,
			awsApi.TemplateTypeStaticWebsite,
			awsApi.SecretsProviderTypeAwsKms,
		},
		ComputeProcessorTypes: []string{
			awsApi.ResourceTypeS3Bucket,
			awsApi.ResourceTypeRdsPostgres,
			awsApi.ResourceTypeRdsMysql,
		},
		StateStoreTypes: []string{
			awsApi.StateStorageTypeS3Bucket,
		},
		SecretsProviderTypes: []string{
			awsApi.SecretsProviderTypeAwsKms,
		},
		PulumiPlugins: []*scpluginv1.PulumiPluginRequirement{
			// pulumi-aws is the big one (~75 MB in the module cache).
			// Pin against api/go.mod — bumping either side without the
			// other replaces every AWS provider instance, which forces
			// a replace cascade across every stack this plugin serves.
			{Package: "aws", Version: "6.83.4"},
			{Package: "awsx", Version: "2.22.0"},
			{Package: "command", Version: "1.2.1"},
			{Package: "docker", Version: "4.11.2"},
			{Package: "random", Version: "4.19.0"},
		},
	}, nil
}

func (p *awsPlugin) pulumiContextFromHeader(ctx context.Context, h *scpluginv1.RequestHeader) (*sdk.Context, func(), error) {
	if h.GetMonitorAddress() == "" {
		return nil, nil, errors.New("no monitor address in request header")
	}
	pctx, err := sdk.NewContext(ctx, sdk.RunInfo{
		MonitorAddr: h.GetMonitorAddress(),
		Project:     h.GetProjectName(),
		Stack:       h.GetStackName(),
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "open pulumi context from monitor address")
	}
	return pctx, func() { pctx.Close() }, nil
}

func (p *awsPlugin) Provider(ctx context.Context, req *scpluginv1.ProviderRequest) (*scpluginv1.ProviderResponse, error) {
	pctx, done, err := p.pulumiContextFromHeader(ctx, req.GetHeader())
	if err != nil {
		return nil, err
	}
	defer done()
	p.progress.Info("provider", fmt.Sprintf("initialising aws provider for %q", req.GetProviderResourceName()))

	cfg := &awsApi.AccountConfig{}
	if err := decodeInputsAs(req.GetInputs(), cfg); err != nil {
		return nil, errors.Wrap(err, "decode AccountConfig from Provider inputs")
	}

	input := api.ResourceInput{
		Descriptor: &api.ResourceDescriptor{
			Type:   awsApi.ProviderType,
			Name:   req.GetProviderResourceName(),
			Config: api.Config{Config: cfg},
		},
		StackParams: &api.StackParams{
			StackName:   req.GetHeader().GetStackName(),
			Environment: req.GetHeader().GetEnvironment(),
		},
	}
	out, err := awsInternal.Provider(pctx, api.Stack{Name: req.GetHeader().GetStackName()}, input, pApi.ProvisionParams{Log: logger.New()})
	if err != nil {
		p.progress.Error("provider", err.Error())
		return nil, err
	}
	urn := waitForRef(out.Ref)
	p.progress.Info("provider", fmt.Sprintf("provider ready (urn=%s)", urn))
	return &scpluginv1.ProviderResponse{ProviderUrn: urn}, nil
}

// provisionFunc is the shared signature across every AWS driver.
type provisionFunc func(*sdk.Context, api.Stack, api.ResourceInput, pApi.ProvisionParams) (*api.ResourceOutput, error)

var provisionDispatch = map[string]provisionFunc{
	awsApi.ResourceTypeS3Bucket:                 awsInternal.S3Bucket,
	awsApi.ResourceTypeEcrRepository:            awsInternal.EcrRepository,
	awsApi.ResourceTypeRdsPostgres:              awsInternal.RdsPostgres,
	awsApi.ResourceTypeRdsMysql:                 awsInternal.RdsMysql,
	awsApi.ResourceTypeCloudTrailSecurityAlerts: awsInternal.CloudTrailSecurityAlerts,
	awsApi.TemplateTypeEcsFargate:               awsInternal.EcsFargate,
	awsApi.TemplateTypeAwsLambda:                awsInternal.Lambda,
	awsApi.TemplateTypeStaticWebsite:            awsInternal.StaticWebsite,
	awsApi.SecretsProviderTypeAwsKms:            awsInternal.KmsKeySecretsProvider,
}

func (p *awsPlugin) Provision(ctx context.Context, req *scpluginv1.ProvisionRequest) (*scpluginv1.ProvisionResponse, error) {
	fn, ok := provisionDispatch[req.GetResourceType()]
	if !ok {
		return nil, errors.Errorf("sc-plugin-aws does not know how to provision %q", req.GetResourceType())
	}

	pctx, done, err := p.pulumiContextFromHeader(ctx, req.GetHeader())
	if err != nil {
		return nil, err
	}
	defer done()
	p.progress.Info("provision", fmt.Sprintf("provisioning %s %q", req.GetResourceType(), req.GetResourceName()))

	cfg, err := decodeTypedConfig(req.GetResourceType(), req.GetInputs())
	if err != nil {
		return nil, err
	}

	input := api.ResourceInput{
		Descriptor: &api.ResourceDescriptor{
			Type:   req.GetResourceType(),
			Name:   req.GetResourceName(),
			Config: api.Config{Config: cfg},
		},
		StackParams: &api.StackParams{
			StackName:   req.GetHeader().GetStackName(),
			Environment: req.GetHeader().GetEnvironment(),
		},
	}
	out, err := fn(pctx, api.Stack{Name: req.GetHeader().GetStackName()}, input, pApi.ProvisionParams{Log: logger.New()})
	if err != nil {
		p.progress.Error("provision", err.Error())
		return nil, err
	}
	urn := waitForRef(out.Ref)
	p.progress.Info("provision", fmt.Sprintf("%s %q registered (urn=%s)", req.GetResourceType(), req.GetResourceName(), urn))
	return &scpluginv1.ProvisionResponse{Urn: urn}, nil
}

// computeFunc is the shared ComputeProcessor signature.
type computeFunc func(*sdk.Context, api.Stack, api.ResourceInput, pApi.ComputeContextCollector, pApi.ProvisionParams) (*api.ResourceOutput, error)

var computeDispatch = map[string]computeFunc{
	awsApi.ResourceTypeS3Bucket:    awsInternal.S3BucketComputeProcessor,
	awsApi.ResourceTypeRdsPostgres: awsInternal.RdsPostgresComputeProcessor,
	awsApi.ResourceTypeRdsMysql:    awsInternal.RdsMysqlComputeProcessor,
}

func (p *awsPlugin) ComputeProcess(ctx context.Context, req *scpluginv1.ComputeProcessRequest) (*scpluginv1.ComputeProcessResponse, error) {
	fn, ok := computeDispatch[req.GetResourceType()]
	if !ok {
		return nil, errors.Errorf("sc-plugin-aws does not expose a ComputeProcessor for %q", req.GetResourceType())
	}

	pctx, done, err := p.pulumiContextFromHeader(ctx, req.GetHeader())
	if err != nil {
		return nil, err
	}
	defer done()
	p.progress.Info("compute-process", fmt.Sprintf("%s %q", req.GetResourceType(), req.GetResourceName()))

	parent := &pApi.ParentInfo{}
	if raw := req.GetParentInfoJson(); len(raw) > 0 {
		if err := yaml.Unmarshal(raw, parent); err != nil {
			return nil, errors.Wrap(err, "decode ParentInfo from compute-process request")
		}
	}

	cfg, err := decodeTypedConfig(req.GetResourceType(), req.GetInputs())
	if err != nil {
		return nil, err
	}

	input := api.ResourceInput{
		Descriptor: &api.ResourceDescriptor{
			Type:   req.GetResourceType(),
			Name:   req.GetResourceName(),
			Config: api.Config{Config: cfg},
		},
		StackParams: &api.StackParams{
			StackName:   req.GetHeader().GetStackName(),
			Environment: req.GetHeader().GetEnvironment(),
		},
	}

	collector := newCapturingCollector()
	_, err = fn(pctx, api.Stack{Name: req.GetHeader().GetStackName()}, input, collector, pApi.ProvisionParams{
		Log:         logger.New(),
		ParentStack: parent,
	})
	if err != nil {
		p.progress.Error("compute-process", err.Error())
		return nil, err
	}

	resp := collector.ToResponse()
	p.progress.Info("compute-process", fmt.Sprintf("emitted %d env var(s) + %d tpl extension(s)", len(resp.GetEnvVars()), len(resp.GetTplExtensions())))
	return resp, nil
}

// InitStateStore — pre-engine. SC core calls this before the Pulumi
// Automation API opens the workspace. The driver sets AWS_* env vars
// in-process (SC core and the plugin share the engine process via
// hashicorp/go-plugin) and returns the s3:// backend URL SC core wires
// into the workspace.
func (p *awsPlugin) InitStateStore(ctx context.Context, req *scpluginv1.InitStateStoreRequest) (*scpluginv1.InitStateStoreResponse, error) {
	cfg := &awsApi.StateStorageConfig{}
	if err := decodeInputsAs(req.GetConfig(), cfg); err != nil {
		return nil, errors.Wrap(err, "decode StateStorageConfig")
	}
	p.progress.Info("state-store", fmt.Sprintf("configuring s3-bucket backend (bucket=%q region=%q)", cfg.BucketName, cfg.Region))
	if err := awsInternal.InitStateStore(ctx, cfg, logger.New()); err != nil {
		p.progress.Error("state-store", err.Error())
		return nil, err
	}
	return &scpluginv1.InitStateStoreResponse{BackendUrl: cfg.StorageUrl()}, nil
}

// InitSecretsProvider — pre-engine. SC core calls this before the Pulumi
// Automation API opens the workspace. Returns the awskms:// URL from the
// configured KeyName; the Pulumi stack secrets-provider rides AWS KMS
// via the ambient credential chain (same env the InitStateStore step
// set up — SC core calls InitStateStore first).
func (p *awsPlugin) InitSecretsProvider(_ context.Context, req *scpluginv1.InitSecretsProviderRequest) (*scpluginv1.InitSecretsProviderResponse, error) {
	cfg := &awsApi.SecretsProviderConfig{}
	if err := decodeInputsAs(req.GetConfig(), cfg); err != nil {
		return nil, errors.Wrap(err, "decode SecretsProviderConfig")
	}
	if cfg.KeyName == "" {
		return nil, errors.New("aws-kms secrets provider requires keyName (awskms://<key>?region=<region>)")
	}
	p.progress.Info("secrets-provider", fmt.Sprintf("configuring aws-kms (key=%q)", cfg.KeyName))
	return &scpluginv1.InitSecretsProviderResponse{ProviderUrl: cfg.KeyUrl()}, nil
}

func (p *awsPlugin) PreDestroy(_ context.Context, req *scpluginv1.PreDestroyRequest) (*scpluginv1.PreDestroyResponse, error) {
	p.progress.Info("pre-destroy", fmt.Sprintf("stack=%q env=%q (no pre-destroy hook configured)", req.GetHeader().GetStackName(), req.GetHeader().GetEnvironment()))
	return &scpluginv1.PreDestroyResponse{}, nil
}

func (p *awsPlugin) LogStream(_ *scpluginv1.LogStreamRequest, stream scpluginv1.SCCloudPlugin_LogStreamServer) error {
	ctx := stream.Context()
	for {
		batch, ok := p.progress.Drain()
		if !ok {
			return nil
		}
		for _, ev := range batch {
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

// decodeTypedConfig picks the correct config shape per resource type.
// Mirrors pulumi/aws/init.go's dispatch — the config decoder used by
// `aws.RegisterProviderConfig` picks the right type on the config
// side, but ComputeProcess/Provision in-plugin need the Go-typed
// struct, so we re-dispatch here.
func decodeTypedConfig(resourceType string, inputs map[string]*scpluginv1.InputValue) (any, error) {
	switch resourceType {
	case awsApi.ResourceTypeS3Bucket:
		cfg := &awsApi.S3Bucket{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.ResourceTypeEcrRepository:
		cfg := &awsApi.EcrRepository{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.ResourceTypeRdsPostgres:
		cfg := &awsApi.PostgresConfig{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.ResourceTypeRdsMysql:
		cfg := &awsApi.MysqlConfig{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.ResourceTypeCloudTrailSecurityAlerts:
		cfg := &awsApi.CloudTrailSecurityAlertsConfig{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.TemplateTypeEcsFargate,
		awsApi.TemplateTypeAwsLambda,
		awsApi.TemplateTypeStaticWebsite:
		cfg := &awsApi.TemplateConfig{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.SecretsProviderTypeAwsKms:
		cfg := &awsApi.SecretsProviderConfig{}
		return cfg, decodeInputsAs(inputs, cfg)
	default:
		return nil, errors.Errorf("sc-plugin-aws has no config decoder for %q", resourceType)
	}
}

// decodeInputsAs lifts the plugin bus's input map into a typed struct
// via YAML round-trip. Same pattern sc-plugin-mongodb /
// sc-plugin-cloudru / sc-plugin-yandex use. Nested shapes (e.g.
// AccountConfig inside TemplateConfig, SecretsBundle inside
// CloudExtras) survive IF the SC-core sidecar serialised them as
// nested maps. Known gap tracked in [07] §8.
func decodeInputsAs[T any](inputs map[string]*scpluginv1.InputValue, out *T) error {
	plain := make(map[string]any, len(inputs))
	for k, v := range inputs {
		switch x := v.GetValue().(type) {
		case *scpluginv1.InputValue_StringValue:
			plain[k] = x.StringValue
		case *scpluginv1.InputValue_BoolValue:
			plain[k] = x.BoolValue
		case *scpluginv1.InputValue_DoubleValue:
			plain[k] = x.DoubleValue
		case *scpluginv1.InputValue_BytesValue:
			plain[k] = string(x.BytesValue)
		}
	}
	b, err := yaml.Marshal(plain)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, out)
}

// waitForRef blocks until a Pulumi Output in a resource ref resolves —
// same reason + same shape as sc-plugin-cloudflare/yandex/cloudru/mongodb.
func waitForRef(ref any) string {
	if ref == nil {
		return ""
	}
	switch r := ref.(type) {
	case string:
		return r
	case sdk.ProviderResource:
		ch := make(chan string, 1)
		r.URN().ApplyT(func(u sdk.URN) sdk.URN {
			select {
			case ch <- string(u):
			default:
			}
			return u
		})
		return <-ch
	case sdk.IDOutput:
		ch := make(chan string, 1)
		r.ApplyT(func(id sdk.ID) sdk.ID {
			select {
			case ch <- string(id):
			default:
			}
			return id
		})
		return <-ch
	case sdk.URNOutput:
		ch := make(chan string, 1)
		r.ApplyT(func(u sdk.URN) sdk.URN {
			select {
			case ch <- string(u):
			default:
			}
			return u
		})
		return <-ch
	default:
		return fmt.Sprintf("%v", r)
	}
}

func main() {
	impl := &awsPlugin{progress: scPlugin.NewPublisher(0)}
	scPlugin.Serve(scPlugin.ServerConfig{
		Impl: impl,
		Logger: hclog.New(&hclog.LoggerOptions{
			Name:   "sc-plugin-aws",
			Level:  hclog.Warn,
			Output: os.Stderr,
		}),
	})
}
