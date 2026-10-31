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

## Optional ECS hardening (S-03, S-12, S-13)

All flags below default to `false`. An unchanged existing stack keeps the
`origin/main` resources and properties: the shared execution/task role and its
permissions, security group rules and attachments, HTTP listener, public-IP
setting, and NLB without security groups. A domain alone does not enable TLS,
so existing Cloudflare Flexible SSL configurations continue using HTTP.

These opt-ins are **recommended for new stacks**. Enabling them on an existing
stack is an explicit migration; review its resource and permission changes first.
Set them in the consuming stack's `cloudExtras`:

```yaml
domain: app.example.com
cloudExtras:
  leastPrivilegeRoles: true
  restrictTaskIngress: true
  enableHTTPS: true
  disablePublicIPWithStaticEgress: true
  # For NEW NLB stacks only (omit for ALBs and existing NLBs):
  # nlbSecurityGroups: true
```

| Flag | Opt-in behavior |
| --- | --- |
| `leastPrivilegeRoles` | Creates a separate `<cluster>-task-role`. The existing execution role gets image-pull/logging permissions and access to this stack's secret ARNs. The runtime role gets ECS Exec channels, mounted EFS filesystem access, and explicit `awsRoles` actions. Both honor `permissionsBoundary`. |
| `restrictTaskIngress` | Limits tasks to the ingress container and health-check ports from the load balancer group; moves the ALB to `-lb-sg` and EFS mount targets to `-efs-sg`, allowing NFS from tasks only. |
| `nlbSecurityGroups` | Attaches `-lb-sg` to an NLB. AWS replaces an existing NLB created without security groups when this is enabled; target groups, listeners and DNS may also change. Use for new NLB stacks. |
| `enableHTTPS` | For an ALB with a domain, requests and validates ACM, adds HTTPS on 443 and redirects HTTP on 80 to HTTPS. The single AWSX HTTP listener retains its `<load-balancer-name>-0` identity. NLB behavior is unchanged. |
| `disablePublicIPWithStaticEgress` | Sets `assignPublicIp: false` only when `staticEgressIP: true` supplies private subnets and NAT. Otherwise public IPs stay enabled, including existing static-egress stacks without this flag. |

With `leastPrivilegeRoles`, workloads requiring runtime Secrets Manager, ECR,
CloudWatch, logs or SSM APIs must explicitly request those actions through
`cloudExtras.awsRoles`. Enabling the flag on an existing shared-role stack can
narrow permissions before its tasks finish rolling; plan that migration. With
the flag omitted, the original broad policy is retained throughout deployment.

With `restrictTaskIngress`, `cloudExtras.securityGroup.ingress` restricts the
load balancer listeners. Explicit address-family lists close the other family
unless listed; empty lists deny ingress. `allowOnlyCloudflare` resolves published
Cloudflare ranges during provisioning. An NLB without `nlbSecurityGroups` keeps
its existing attachment behavior; restricted tasks trust NLB subnet CIDRs on
app/health ports (client IP preservation must remain disabled). Frontend CIDR
and Cloudflare allowlists cannot filter NLB clients in this combination because
the NLB has no group; use `nlbSecurityGroups` on a new NLB to enforce them.
Hosts in those subnets can also reach those ports. Without `restrictTaskIngress`, the original
custom security group processing and shared ALB/task/EFS group remain intact.

With `enableHTTPS`, the registrar must control the domain and support CNAME
records. The validation CNAME is DNS-only; keep it for renewal. The current
registrar interface requires a resolved string record name/type, so ACM's
validation record is created in `ApplyT`; registering it before that requires a
core registrar API change. The validation waiter depends on its returned output.
The HTTP redirect preserves host, path and query and TLS uses
`ELBSecurityPolicy-TLS13-1-2-2021-06`. Cloudflare must use **Full (strict)** when
enabling this flag; Flexible SSL would redirect in a loop. When omitted, no ACM
resources, validation records, HTTPS listener or redirect are introduced.
