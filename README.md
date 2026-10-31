# sc-plugin-aws

The AWS plugin for Simple Container. Extracted from
`pkg/clouds/{aws,pulumi/aws}` + `cmd/cloud-helpers/` in
`simple-container-com/api` per Phase 3+ of the plugin-architecture
roadmap. Fifth plugin in the series (after cloudflare, yandex, cloudru,
mongodb).

Operators who deploy any of the AWS discriminators below in a parent
stack need this plugin loaded; see the
[Upgrading to Plugins](https://github.com/simple-container-com/api/blob/main/docs/docs/guides/upgrading-to-plugins.md)
guide — SC's parse-time fool-protection auto-resolves the latest
release unless an operator pins a specific version via
`plugins.aws.source.version`.

## Shipped scope (v1)

**Providers / state / secrets:**
- `aws` provider (`aws:index/provider:Provider`)
- `s3-bucket` state backend (via `aws-token` auth)
- `aws-kms` stack-secrets provider + the KMS-key resource that backs it

**Resources:**
- `s3-bucket`
- `ecr-repository`
- `aws-rds-postgres`
- `aws-rds-mysql`
- `aws-cloudtrail-security-alerts` (CloudTrail metric filters + alarms
  for SOC2 CC6.1 / CC7.1, ISO 27001 A.8.2 / A.8.15 / A.8.16)

**Templates:**
- `ecs-fargate` (cloud-compose)
- `aws-lambda` (single-image)
- `aws-static-website` (static-site)

**ComputeProcessors:** `s3-bucket`, `aws-rds-postgres`, `aws-rds-mysql`
— emit `<PREFIX>_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_URI` /
`_DB` env vars + resource tpl extensions to consuming compose/k3s
stacks via the Phase 1e proto ComputeProcess v2.

**Cloud helpers:** `sc-helper-aws-cloudwatch-alert-lambda` +
`sc-helper-aws-health-bridge-lambda` — the runtime handlers for
CloudWatch-alarm and AWS-Health-event notifications. These ship as the
separate `cloud-helpers` Lambda binary in this release.

## Deferred (follow-up)

- **PeerInvoke exposure** of `LookupSubnetsInAccount` +
  `NewVpcInAccount` so `sc-plugin-mongodb` v2 can broker a
  SecurityGroup + VpcEndpoint for PrivateLink without a Go-module
  dependency. Blocked on the `SCCore.PeerInvoke` callback RPC — only
  the plugin-side `BrokerAware` scaffold has shipped (api #509).

## Repo layout

```
sc-plugin-aws/
├── api/                               ← config tier. Own Go module; SC core imports it.
│   ├── init.go                        ← RegisterProviderConfig + RegisterPluginRequirement
│   ├── aws.go                         ← TemplateConfig, CloudExtras, SecurityGroup, SecretsBundle
│   ├── auth.go                        ← AccountConfig, state/secrets provider configs
│   ├── bucket.go / ecr_repository.go / rds_postgres.go / rds_mysql.go / aws_lambda.go
│   ├── ecs_fargate.go / static_website.go / cloudtrail_security_alerts.go
│   └── go.mod                         ← depends only on simple-container-com/api
└── plugin/                            ← driver tier. Own Go module; the plugin binary.
    ├── cmd/
    │   ├── sc-plugin-aws/main.go      ← gRPC plugin server over hashicorp/go-plugin
    │   └── cloud-helpers/main.go      ← AWS Lambda runtime for alert handlers
    ├── internal/                      ← lifted Pulumi driver code (ex pkg/clouds/pulumi/aws)
    │   ├── provider.go / bucket.go / aws_lambda.go / ecs_fargate.go / ...
    │   ├── compute_proc.go            ← S3 + RDS compute processors
    │   └── helpers/                   ← CloudWatch-alert / Health-bridge Lambda handlers
    └── go.mod                         ← pulumi-aws + pulumi-awsx + aws-sdk-go-v2/cloudtrail
                                         + aws-sdk-go-v2/cloudwatchlogs + aws-lambda-go
```

## Binary payoff

Dropping the AWS driver tree + its helpers out of
`simple-container-com/api` cuts `dist/sc` by ~25-35 MB:
- `pulumi-aws/sdk/v6` v6.83.4 — the dominant delta (~75 MB in the
  module cache; ~20 MB of generated code in the sc binary itself)
- `pulumi-awsx/sdk/v2` v2.22.0 — ECS + ALB higher-level resources
- `aws-sdk-go-v2/service/cloudtrail` + `aws-sdk-go-v2/service/cloudwatchlogs`

What stays in SC core:
- `aws-sdk-go-v2` base + `/config` + `/credentials` + `/service/kms` —
  consumed by `pkg/api/secrets/scoped/{kms,opener}.go` for scopes.yaml
  per-value KMS encryption (the `awskms://` recipient URL scheme). This
  is a SEPARATE surface from the `aws-kms` Pulumi stack-secrets
  provider that moves with this plugin.

## Where tests live

Unit tests live inside their respective packages (`api/*_test.go`,
`plugin/internal/*_test.go`, `plugin/internal/helpers/*_test.go`).
Live end-to-end smokes happen against a staging stack from
`simple-container-com/api`'s own CI pipeline after an operator pins
`plugins.aws:` in the staging parent stack's `server.yaml`.

## Non-destroy invariant

Changing config in the parent stack **must not** replace any AWS
resource (S3 bucket, RDS instance, ECR repo, Lambda, ECS service,
CloudTrail trail, …). The migration from in-tree to plugin preserves
every URN. See
[`04-no-destroy-invariant.md`](https://github.com/simple-container-com/forge/blob/main/docs/design/2026-10-24/sc-plugin-architecture/04-no-destroy-invariant.md).

## ECS task permissions (S-03)

ECS uses separate execution and runtime roles. The execution role retains
image-pull and logging permissions, and can read only the Secrets Manager
ARNs created for this stack. Containers receive injected values without
receiving Secrets Manager or ECR API permissions. The runtime role permits
ECS Exec channels and, for mounted volumes, access to the stack's EFS filesystems.
Both roles honor `permissionsBoundary`.

Existing explicit `cloudExtras.awsRoles` actions now apply only to the runtime
role. For example, `cloudExtras: {awsRoles: ["s3:GetObject"]}` grants that action
on `*`, preserving the existing configuration contract. Request additional
runtime permissions deliberately; workloads relying on previously implicit
Secrets Manager/ECR access must declare those actions. The execution role,
policy and attachment retain their identities; task definitions roll to the
separate runtime role without replacing the ECS service.
