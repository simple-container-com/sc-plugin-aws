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
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"sync"

	"gopkg.in/yaml.v3"

	hclog "github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/pkg/errors"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/internals"
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
	// broker is captured in SetBroker (the BrokerAware opt-in from
	// api #509). PeerClient uses it to dial SC core's SCCore endpoint
	// for PeerInvoke — our one way to reach the registrar plugin
	// (cloudflare) that owns DNS for an AWS-provisioned Lambda / ECS /
	// static-site domain.
	broker *hplugin.GRPCBroker
}

// SetBroker implements scPlugin.BrokerAware. hashicorp/go-plugin hands
// the broker to the plugin at GRPCServer time; scPlugin.scCloudPlugin
// forwards it here so handlers can later call NewPeerClient.
func (p *awsPlugin) SetBroker(b *hplugin.GRPCBroker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.broker = b
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
	// EngineAddr is required for ctx.Log to work: without it, logState's
	// engine conn is nil and ctx.Log.Warn / Info panic with a nil deref
	// deep inside pulumi/sdk/v3/go/pulumi/log.go:_log. pulumi-aws's
	// drivers call Log on resolve paths (resolveDeployImageRef in
	// pkg/clouds/pulumi/docker/build_and_push.go uses it when deploying
	// a tag because no immutable digest resolved), so a missing
	// EngineAddr turns into a background goroutine panic that exits
	// status 2 → SC core's engine sees "waiting for RPCs: EOF".
	pctx, err := sdk.NewContext(ctx, sdk.RunInfo{
		MonitorAddr: h.GetMonitorAddress(),
		EngineAddr:  h.GetEngineAddress(),
		Project:     h.GetProjectName(),
		Stack:       h.GetStackName(),
		// DryRun landed on RequestHeader via api v2026.10.60 (api#527).
		// aws has no `ctx.DryRun()` guard today but future preview-skip
		// code paths need the pctx aligned with reality — same uptake
		// shape as sc-plugin-mongodb#6, sc-plugin-cloudflare#3.
		DryRun: h.GetDryRun(),
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "open pulumi context from monitor address")
	}
	return pctx, func() { pctx.Close() }, nil
}

func (p *awsPlugin) Provider(ctx context.Context, req *scpluginv1.ProviderRequest) (*scpluginv1.ProviderResponse, error) {
	pctx, _, err := p.pulumiContextFromHeader(ctx, req.GetHeader())
	if err != nil {
		return nil, err
	}
	// DO NOT close pctx — same reason as Provision below and
	// sc-plugin-mongodb's Provider handler: closing pctx cuts off any
	// in-flight RegisterResource RPCs, which drops the plugin's URN
	// registrations and plans a destroy of every pre-existing state
	// entry. Explicitly the cascade bug Addendum U of
	// forge/docs/design/2026-10-24/sc-plugin-architecture/04-no-destroy-invariant.md
	// documents. Provider only emits one register (the aws provider
	// URN itself) but the invariant is uniform — every RPC handler in
	// every plugin leaks the pctx until plugin shutdown.
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
	out, err := awsInternal.Provider(pctx, api.Stack{Name: req.GetHeader().GetStackName()}, input, pApi.ProvisionParams{Log: logger.New(), ComputeContext: newCapturingCollector()})
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

func (p *awsPlugin) Provision(ctx context.Context, req *scpluginv1.ProvisionRequest) (resp *scpluginv1.ProvisionResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			// Log to a file too — hashicorp/go-plugin's stderr forwarding
			// doesn't always surface panics.
			_ = os.WriteFile("/tmp/sc-plugin-aws-panic.log", []byte(fmt.Sprintf("Provision panic: %v\n%s\n", r, stack)), 0o644)
			fmt.Fprintf(os.Stderr, "sc-plugin-aws Provision panic: %v\n%s\n", r, stack)
			err = fmt.Errorf("sc-plugin-aws Provision panic: %v\n%s", r, stack)
		}
	}()
	fn, ok := provisionDispatch[req.GetResourceType()]
	if !ok {
		return nil, errors.Errorf("sc-plugin-aws does not know how to provision %q", req.GetResourceType())
	}

	pctx, _, err := p.pulumiContextFromHeader(ctx, req.GetHeader())
	if err != nil {
		return nil, err
	}
	// DO NOT close pctx here: closing it before every ApplyT chain the
	// AWS driver scheduled has drained panics in a background goroutine
	// (visible as `exit status 2` + `error reading from server: EOF`
	// at the engine side, with no stack because the ApplyT runs inside
	// pulumi-aws's own code). The pctx is cheap to leak until plugin
	// shutdown — one TCP connection to SC core's monitor per RPC.
	p.progress.Info("provision", fmt.Sprintf("provisioning %s %q", req.GetResourceType(), req.GetResourceName()))

	cfg, err := decodeTypedConfig(req.GetResourceType(), req.GetInputs())
	if err != nil {
		return nil, err
	}

	// `input.StackParams.StackName` must carry the PARENT CLI name
	// ("forge-notifier"), not the CHILD stack name
	// ("forge-notifier--staging"), so drivers that name resources off
	// `deployParams.StackName` — most notably `toSecretName(deployParams, …)`
	// in secrets.go, which produced `forge-notifier--staging--values----*`
	// on state — keep producing byte-identical URNs post-split. The in-tree
	// deploy path set `StackParams.StackName` to the CLI value
	// (`params.StackName`). Fall back to `Header.StackName` when the core
	// is pre-cli_stack_name (older SC without the field) — still CHILD,
	// but at least non-empty.
	cliStackName := req.GetHeader().GetCliStackName()
	if cliStackName == "" {
		cliStackName = req.GetHeader().GetStackName()
	}
	input := api.ResourceInput{
		Descriptor: &api.ResourceDescriptor{
			Type:   req.GetResourceType(),
			Name:   req.GetResourceName(),
			Config: api.Config{Config: cfg},
		},
		StackParams: &api.StackParams{
			StackName:   cliStackName,
			Environment: req.GetHeader().GetEnvironment(),
		},
	}

	// Build an aws Pulumi provider INSIDE the plugin's own pctx. A
	// ProviderResource from SC core's pctx cannot cross the bus
	// (hangs silently — memory sc_plugin_provider_cannot_cross_pctx),
	// so the plugin reconstructs the provider byte-identically from
	// the AccountConfig embedded in the resource config. Same name,
	// same inputs → same URN → Pulumi reuses the existing state entry.
	//
	// Provider resource name mirrors SC core's in-tree formula at
	// pkg/clouds/pulumi/provision.go:398:
	//     <stack.Name>--<resType>--<resName>--<env>--provider
	// so the Pulumi URN matches byte-identically with the pre-plugin
	// state and avoids a replace cascade on every AWS resource.
	// Match the in-tree formula at pkg/clouds/pulumi/provision.go:398
	// EXACTLY: Descriptor.Name = <stack>--<resType>--<resName>--<env>--provider,
	// AND Environment is set so sdkAws.NewProvider's ToResName appends
	// another "--<env>" to the resource key — yielding the URN
	// "<stack>--<resType>--<resName>--<env>--provider--<env>" the
	// pre-plugin state already holds.
	providerResName := fmt.Sprintf("%s--%s--%s--%s--provider",
		req.GetHeader().GetStackName(), req.GetResourceType(), req.GetResourceName(), req.GetHeader().GetEnvironment())
	provider, perr := p.buildAwsProvider(pctx, cfg, req.GetHeader().GetStackName(), providerResName, req.GetHeader().GetEnvironment())
	if perr != nil {
		return nil, errors.Wrap(perr, "build aws provider inside plugin pctx")
	}

	params := pApi.ProvisionParams{
		Log:              logger.New(),
		ComputeContext:   newCapturingCollector(),
		Provider:         provider,
		BaseEnvVariables: map[string]string{},
	}

	// Bridge the registrar across the bus if the deploying stack has
	// one. SC core packs the registrar's plugin coordinates in the
	// request (sidecar fills them from a *pluginRegistrar it already
	// built); the AWS Lambda / static-site drivers can then call
	// params.Registrar.ProvisionDomainForEndpoint without caring that
	// cloudflare lives in another process.
	if rpn := req.GetRegistrarPluginName(); rpn != "" {
		p.mu.Lock()
		broker := p.broker
		p.mu.Unlock()
		if broker == nil {
			return nil, errors.New("registrar bridge requested but SetBroker was never called; plugin wiring is broken")
		}
		peer, perr := scPlugin.NewPeerClient(ctx, broker, req.GetHeader())
		if perr != nil {
			return nil, errors.Wrap(perr, "open PeerClient to SC core for registrar bridge")
		}
		defer peer.Close()
		params.Registrar = newSCCoreRegistrar(peer, req.GetHeader(), rpn, req.GetRegistrarType(), req.GetRegistrarMainDomain())
	}
	out, err := fn(pctx, api.Stack{Name: req.GetHeader().GetStackName()}, input, params)
	if err != nil {
		p.progress.Error("provision", err.Error())
		return nil, err
	}
	// Drain the pulumi.Context before returning: RegisterResource spawns
	// goroutines that call monitor.RegisterResource(ctx, ...) in the
	// background, so a direct `fn(pctx, ...)` returns before any of the
	// sub-resources (ECR, IAM role, Lambda function, schedule rules,
	// permissions, secrets) have reached the monitor. Without this the
	// engine's plan phase sees zero RegisterResource calls from this
	// Provision and marks every pre-existing resource for delete.
	// RunWithContext does the same drain but also registers a root
	// `pulumi:pulumi:Stack` whose URN collides with SC core's — see
	// drain.go for why we hand-roll ctx.wait() instead.
	if werr := drainContext(pctx); werr != nil {
		p.progress.Error("provision", "drain: "+werr.Error())
		return nil, werr
	}
	urn := waitForRef(out.Ref)
	// Harvest the pctx's exports and hand them back on the wire. SC core
	// re-exports them against its OWN pctx so they land in the parent
	// stack root's RegisterResourceOutputs call — without this,
	// `ctx.Export(k, v)` on the plugin's pctx stays in the plugin and
	// never reaches the parent stack root; every downstream
	// `uses: [forge-storage]` compute-processor's
	// `GetParentOutput(parentRef, bucketNameExport)` returns empty.
	//
	// Latent since the plugin split — the reason it hasn't bitten is
	// that forge-* services deployed BEFORE the split had the s3 exports
	// written by the in-tree code into their state, and those stale
	// exports are still cached. Any new/re-created forge-* stack would
	// hit the same empty lookup the mongodb side did on 2026-10-31
	// post-cascade. Addendum V of
	// forge/docs/design/2026-10-24/sc-plugin-architecture/04-no-destroy-invariant.md
	// documents this as the ninth plugin-split defect.
	//
	// Needs SC core from api v2026.10.60+ (api#527's resp.GetOutputs()
	// consumer). Older cores drop the field.
	exports, exportsErr := harvestPctxExports(ctx, pctx)
	if exportsErr != nil {
		p.progress.Warn("provision", "harvest exports: "+exportsErr.Error())
	}
	p.progress.Info("provision", fmt.Sprintf("%s %q registered (urn=%s, exports=%d)", req.GetResourceType(), req.GetResourceName(), urn, len(exports)))
	return &scpluginv1.ProvisionResponse{Urn: urn, Outputs: exports}, nil
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

	pctx, _, err := p.pulumiContextFromHeader(ctx, req.GetHeader())
	if err != nil {
		return nil, err
	}
	// DO NOT close pctx — same reason as Provider/Provision above.
	// ComputeProcess invokes the per-resource compute processor
	// (S3BucketComputeProcessor, RdsPostgresComputeProcessor, …) which
	// may register sub-resources (DatabaseUser, IAM bindings) whose
	// RegisterResource RPCs ride ApplyT goroutines; closing pctx on
	// return drops those in flight.
	p.progress.Info("compute-process", fmt.Sprintf("%s %q", req.GetResourceType(), req.GetResourceName()))

	parent := &pApi.ParentInfo{}
	if raw := req.GetParentInfoJson(); len(raw) > 0 {
		// json.Unmarshal (NOT yaml.Unmarshal): SC core marshals
		// pApi.ParentInfo via json.Marshal, and the struct has no
		// yaml tags, so a YAML read would look for lowercase keys
		// (`stackname`, `fullreference`) while the JSON wrote them
		// capitalized (`StackName`, `FullReference`) — every field
		// would stay empty, and the mongodb ComputeProcessor's
		// `<FullReference>--mongodb--<env>-id` becomes a dangling
		// StackReference. (same bug exists in the mongodb plugin;
		// fix independently when touching that repo.)
		if err := json.Unmarshal(raw, parent); err != nil {
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
// Automation API opens the workspace, and uses the response to:
// (a) set `PULUMI_BACKEND_URL` to the returned s3:// URL, and
// (b) `os.Setenv` every key/value in `resp.Env` into SC core's
// process (per plugin_sidecars.go makeStateStoreSidecar).
//
// Credentials live inside `cfg.Credentials.Credentials` as a resolved
// JSON blob (the `${auth:aws}` reference the parent stack expanded).
// `api.ConvertAuth` deserialises it into a populated `AccountConfig`,
// from which we lift AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, and
// AWS_DEFAULT_REGION for SC core's S3 client in `login.go` →
// `pulumi/backend/filestate` → `gocloud.dev/blob/s3blob`.
//
// Setting env in the plugin's own process is NOT enough — SC core
// and the plugin are separate OS processes under hashicorp/go-plugin,
// so os.Setenv does not cross the boundary (live-caught on
// forge-notifier staging redeploy 2026-10-30).
func (p *awsPlugin) InitStateStore(_ context.Context, req *scpluginv1.InitStateStoreRequest) (*scpluginv1.InitStateStoreResponse, error) {
	cfg := &awsApi.StateStorageConfig{}
	if err := decodeInputsAs(req.GetConfig(), cfg); err != nil {
		return nil, errors.Wrap(err, "decode StateStorageConfig")
	}

	var creds awsApi.AccountConfig
	if cfg.CredentialsValue() != "" {
		if err := api.ConvertAuth(cfg, &creds); err != nil {
			return nil, errors.Wrap(err, "convert aws-token credentials to AccountConfig")
		}
	}
	// The stack-level AccountConfig fields win over the auth-level ones
	// (if the operator overrides them at the state-storage block).
	if cfg.AccessKey != "" {
		creds.AccessKey = cfg.AccessKey
	}
	if cfg.SecretAccessKey != "" {
		creds.SecretAccessKey = cfg.SecretAccessKey
	}
	if cfg.Region != "" {
		creds.Region = cfg.Region
	}

	p.progress.Info("state-store", fmt.Sprintf("configuring s3-bucket backend (bucket=%q region=%q)", cfg.BucketName, creds.Region))

	env := map[string]*scpluginv1.InputValue{}
	setStr := func(k, v string) {
		if v == "" {
			return
		}
		env[k] = &scpluginv1.InputValue{Value: &scpluginv1.InputValue_StringValue{StringValue: v}}
	}
	setStr("AWS_ACCESS_KEY", creds.AccessKey)
	setStr("AWS_ACCESS_KEY_ID", creds.AccessKey)
	setStr("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	setStr("AWS_DEFAULT_REGION", creds.Region)
	setStr("AWS_REGION", creds.Region)

	return &scpluginv1.InitStateStoreResponse{
		BackendUrl: cfg.StorageUrl(),
		Env:        env,
	}, nil
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

// buildAwsProvider constructs an aws Pulumi provider inside the
// plugin's own pctx, byte-identical by URN to the one SC core
// registered via the Provider RPC. The provider CANNOT cross RPC
// boundaries (memory sc_plugin_provider_cannot_cross_pctx), so each
// Provision call rebuilds it from the AccountConfig embedded in the
// resource config. The provider name mirrors
// `input.ToResName(req.ProviderResourceName)` SC core uses — the
// convention is `<provider-type>--<env>` for the registered provider.
func (p *awsPlugin) buildAwsProvider(pctx *sdk.Context, cfg any, stackName, providerResName, environment string) (sdk.ProviderResource, error) {
	authCfg, ok := cfg.(api.AuthConfig)
	if !ok {
		return nil, errors.Errorf("decoded config (%T) does not implement api.AuthConfig — cannot derive AWS credentials", cfg)
	}
	var accountCfg awsApi.AccountConfig
	if authCfg.CredentialsValue() != "" {
		if err := api.ConvertAuth(authCfg, &accountCfg); err != nil {
			return nil, errors.Wrap(err, "convert aws-token credentials to AccountConfig")
		}
	}
	providerInput := api.ResourceInput{
		Descriptor: &api.ResourceDescriptor{
			Type:   awsApi.ProviderType,
			Name:   providerResName,
			Config: api.Config{Config: &accountCfg},
		},
		StackParams: &api.StackParams{
			StackName:   stackName,
			Environment: environment,
		},
	}
	out, err := awsInternal.Provider(pctx, api.Stack{Name: stackName}, providerInput, pApi.ProvisionParams{Log: logger.New(), ComputeContext: newCapturingCollector()})
	if err != nil {
		return nil, err
	}
	if pr, ok := out.Ref.(sdk.ProviderResource); ok {
		return pr, nil
	}
	return nil, errors.Errorf("awsInternal.Provider returned a non-ProviderResource ref (%T)", out.Ref)
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
	case awsApi.TemplateTypeEcsFargate:
		// SC core runs ToEcsFargateConfig server-side; the Inputs
		// map SC-core sends is the serialised *EcsFargateInput. The
		// in-tree driver type-asserts `input.Descriptor.Config.Config`
		// as `*EcsFargateInput`, so decode into that same shape.
		cfg := &awsApi.EcsFargateInput{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.TemplateTypeAwsLambda:
		cfg := &awsApi.LambdaInput{}
		return cfg, decodeInputsAs(inputs, cfg)
	case awsApi.TemplateTypeStaticWebsite:
		cfg := &awsApi.StaticSiteInput{}
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
		plain[k] = unwrapInputValue(v)
	}
	b, err := yaml.Marshal(plain)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, out)
}

// unwrapInputValue recursively flattens an InputValue tree back into
// Go types the yaml round-trip can unmarshal into a typed struct.
// Scalar-only decoding (the earlier shape) dropped every nested map
// and list, so a stackConfig.image.* block arrived as a bare
// stackConfig key with no value, and the AWS Lambda driver panicked
// dereferencing `*ContainerImage`. Live-caught against forge-notifier
// staging preview 2026-10-30.
func unwrapInputValue(v *scpluginv1.InputValue) any {
	if v == nil {
		return nil
	}
	switch x := v.GetValue().(type) {
	case *scpluginv1.InputValue_StringValue:
		return x.StringValue
	case *scpluginv1.InputValue_BoolValue:
		return x.BoolValue
	case *scpluginv1.InputValue_DoubleValue:
		return x.DoubleValue
	case *scpluginv1.InputValue_BytesValue:
		return string(x.BytesValue)
	case *scpluginv1.InputValue_MapValue:
		m := make(map[string]any, len(x.MapValue.GetFields()))
		for k, iv := range x.MapValue.GetFields() {
			m[k] = unwrapInputValue(iv)
		}
		return m
	case *scpluginv1.InputValue_ListValue:
		items := x.ListValue.GetItems()
		out := make([]any, len(items))
		for i, iv := range items {
			out[i] = unwrapInputValue(iv)
		}
		return out
	}
	return nil
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
	// Full goroutine traces on panic so a crash points at the
	// faulting driver, not just the gRPC handler frame.
	_ = os.Setenv("GOTRACEBACK", "all")
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

// harvestPctxExports reads every `pctx.Export(k, v)` call made during the
// RPC handler and converts each value into an InputValue the wire can
// carry. Awaits every sdk.Output so a late-resolving ApplyT chain (bucket
// Arn, access key, etc.) lands as a concrete string on apply — remains
// unknown during preview, which is expected.
//
// Verbatim port from sc-plugin-mongodb#6 — same shape, same reason, same
// gap in the plugin split. See Addendum V of
// forge/docs/design/2026-10-24/sc-plugin-architecture/04-no-destroy-invariant.md
// for the full narrative. SC core re-exports whatever this returns onto
// its own pctx at `plugin_sidecars.go:209` (api v2026.10.60+).
func harvestPctxExports(ctx context.Context, pctx *sdk.Context) (map[string]*scpluginv1.InputValue, error) {
	raw := pctx.GetCurrentExportMap()
	out := make(map[string]*scpluginv1.InputValue, len(raw))
	for k, v := range raw {
		plain, err := awaitInputToPlain(ctx, v)
		if err != nil {
			return out, errors.Wrapf(err, "await export %q", k)
		}
		if iv := anyToInputValue(plain); iv != nil {
			out[k] = iv
		}
	}
	return out, nil
}

func awaitInputToPlain(ctx context.Context, v sdk.Input) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch tv := v.(type) {
	case sdk.String:
		return string(tv), nil
	case sdk.Bool:
		return bool(tv), nil
	case sdk.Int:
		return int(tv), nil
	case sdk.Float64:
		return float64(tv), nil
	}
	if out, ok := v.(sdk.Output); ok {
		resolved, aerr := internals.UnsafeAwaitOutput(ctx, out)
		if aerr != nil {
			return nil, aerr
		}
		return unwrapPlain(resolved.Value), nil
	}
	return nil, nil
}

func unwrapPlain(v any) any {
	switch tv := v.(type) {
	case sdk.URN:
		return string(tv)
	case sdk.ID:
		return string(tv)
	}
	return v
}

func anyToInputValue(v any) *scpluginv1.InputValue {
	if v == nil {
		return nil
	}
	switch sv := v.(type) {
	case string:
		if sv == "" {
			return nil
		}
		return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_StringValue{StringValue: sv}}
	case bool:
		return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_BoolValue{BoolValue: sv}}
	case int:
		return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_IntValue{IntValue: int64(sv)}}
	case int64:
		return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_IntValue{IntValue: sv}}
	case float64:
		return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_DoubleValue{DoubleValue: sv}}
	case []byte:
		return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_BytesValue{BytesValue: sv}}
	}
	return nil
}
