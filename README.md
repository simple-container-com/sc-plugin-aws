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
- `aws-ses-smtp-user` (Amazon SES SMTP credentials; see
  [below](#ses-smtp-credentials-aws-ses-smtp-user))

**Templates:**
- `ecs-fargate` (cloud-compose)
- `aws-lambda` (single-image)
- `aws-static-website` (static-site)

**ComputeProcessors:** `s3-bucket`, `aws-rds-postgres`, `aws-rds-mysql`,
`aws-ses-smtp-user` — emit `<PREFIX>_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_URI` /
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
│   ├── ses_smtp_user.go
│   ├── ecs_fargate.go / static_website.go / cloudtrail_security_alerts.go
│   └── go.mod                         ← depends only on simple-container-com/api
└── plugin/                            ← driver tier. Own Go module; the plugin binary.
    ├── cmd/
    │   ├── sc-plugin-aws/main.go      ← gRPC plugin server over hashicorp/go-plugin
    │   └── cloud-helpers/main.go      ← AWS Lambda runtime for alert handlers
    ├── internal/                      ← lifted Pulumi driver code (ex pkg/clouds/pulumi/aws)
    │   ├── provider.go / bucket.go / aws_lambda.go / ecs_fargate.go / ...
    │   ├── compute_proc.go            ← S3 + RDS compute processors
    │   ├── ses_smtp_user.go           ← SES SMTP user + its compute processor
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

## Per-container ECS secrets

For `ecs-fargate` cloud-compose stacks, set `config.cloudExtras.containerSecrets`
in the consuming stack's `client.yaml`. Keys are compose service names from
`config.runs`; values are allowlists of **secret environment variable names**:

```yaml
config:
  runs: [gateway, identity, profiles]
  cloudExtras:
    containerSecrets:
      gateway: []
      identity: [MONGO_URI, SIGNING_KEY_PEM, MAIL_URL]
      profiles: [MONGO_URI, PROFILES_SERVICE_KEY]
  secrets:
    MONGO_URI: ${resource:mongodb.uri}
    SIGNING_KEY_PEM: ${secret:signing-key}
    MAIL_URL: ${secret:mail-url}
    PROFILES_SERVICE_KEY: ${secret:profiles-service-key}
```

An omitted `containerSecrets` block or an empty map keeps existing behavior.
When the map is configured, an omitted service entry receives every available
stack and resource/context secret. A present service entry restricts injection to its
listed names; `[]` injects none. List every service, including the
gateway, to scope the whole task. Duplicate names do not duplicate injection.
Use an explicit `[]` for an empty list: SC's RPC transport omits YAML `null`
map entries, which would leave the service with the legacy default.

Names can refer to `config.secrets` or secret env variables supplied by compute
resources (for example a resource's `MONGO_URI`). Unknown containers are rejected
during conversion and checked again by the plugin for older cores. Unknown secret
names, including ordinary env names, are rejected before the cluster creates
resources, once resource/context env variables are available. Errors identify
names without revealing secret values.

Each secret is still created once in Secrets Manager, with the existing names,
values, stack-over-context precedence, and ECS `valueFrom` ARN references. The
allowlist filters ECS secret injection only. Plain compose, stack and context env
keep their existing behavior, and a secret excluded from a container cannot fall
back to that container's compose/stack env entry of the same name. Keep secret
values in `config.secrets` or resource outputs; this does not add SC
`${secret:...}` interpolation to compose `environment` or compose file mounts.

This uses the raw `stackConfig.cloudExtras` transport restored in PR #5, so a
core whose linked AWS converter predates `containerSecrets` can still pass the
setting to an updated plugin. No compose edit is required. The existing
`EcsFargateContainer.Secrets` value map is not repurposed as an allowlist.
For a nonempty `containerSecrets` map, the plugin also reads secret compute env
variables from core's provisioning request. The legacy plugin ignored that
request context; stacks without allowlists and ordinary context env retain
their previous behavior. Resource-only names require a core that sends
`ProvisionRequest.compute_env_vars` (as the current core does).

Containers in one task still share its network namespace and task IAM role.
This setting limits injected process environments; it does not create separate
IAM identities. With the legacy shared execution/task role, workloads can still
read task secrets through AWS APIs. Combine with `leastPrivilegeRoles` and avoid
granting the runtime role secret-read actions when that access is unnecessary.

## ECS rolling-update percentages

By default an `ecs-fargate` service deploys with `minimumHealthyPercent: 100`
and `maximumPercent: 200`: ECS starts the new task before stopping the old one.
A single-task service that holds an exclusive lock on shared storage (for
example a database whose datadir is on EFS) cannot run two tasks at once, so
the new task fails and the rollout never finishes. Set
`config.cloudExtras.rollingUpdate` in the stack's `client.yaml` to stop the old
task first:

```yaml
config:
  cloudExtras:
    rollingUpdate:
      minHealthyPercent: 0   # 0-100, default 100
      maxPercent: 100        # 100-200, default 200
```

An omitted block or field keeps its default, so existing stacks see no change to
their `deploymentConfiguration`. An explicit `0` is honoured. `maxPercent` must
be greater than `minHealthyPercent` (100/100, including `maxPercent: 100` with
the default minimum, is rejected because the deployment could never progress).
Invalid values fail conversion, and the plugin checks again before creating
resources. With `0`/`100` the service is unavailable between the old task
stopping and the new one passing health checks.

Like `containerSecrets`, this travels in the raw `stackConfig.cloudExtras`
block, so it needs only this plugin release, not a new SC core.

## SES SMTP credentials (`aws-ses-smtp-user`)

Declared in a parent stack's `server.yaml`, `aws-ses-smtp-user` creates:

- an IAM user dedicated to SES sending;
- an inline policy allowing only `ses:SendRawEmail` (the one action the SES
  SMTP interface uses) on the listed SES identities, plus the configuration
  set if one is given, optionally restricted by a `ses:FromAddress`
  `StringLike` condition;
- an access key, whose secret is converted into the SES SMTP password
  (SigV4, region-specific).

It does **not** manage SES identities, DKIM or DNS: verify the domain and get
production access out of band first.

```yaml
# .sc/stacks/<parent>/server.yaml
plugins:
  aws:
    source:
      type: github-release
      repository: simple-container-com/sc-plugin-aws
      version: <a release that includes aws-ses-smtp-user>

resources:
  resources:
    prod:
      resources:
        mautic-ses:
          type: aws-ses-smtp-user
          config:
            credentials: "${auth:aws}"
            account: "${auth:aws.projectId}"
            region: eu-central-1         # SES region; defaults to the credentials' region
            identities:                  # verified domains / addresses, or full identity ARNs
              - innmind.com
            # configurationSet: mautic   # optional; also allowed in the policy
            # fromAddresses:             # optional ses:FromAddress allowlist
            #   - "*@innmind.com"
```

| Config | Required | Meaning |
| --- | --- | --- |
| `identities` | yes | SES identities the user may send as. A bare name becomes `arn:aws:ses:<region>:<account>:identity/<name>`; values starting with `arn:` are used as-is. |
| `region` | no | SES region of the SMTP endpoint and password. Defaults to the region of the `${auth:...}` credentials. |
| `account` | no | Account ID for the identity ARNs. Defaults to the credentials' account, else `sts:GetCallerIdentity`. |
| `configurationSet` | no | Configuration set name; added to the policy resources and exposed as `configuration-set`. |
| `fromAddresses` | no | `ses:FromAddress` patterns (`StringLike`, wildcards allowed). |
| `name` | no | Base name of the IAM resources (defaults to the resource name). |

The parent stack exports `<name>--<env>-ses-smtp-username`,
`-ses-smtp-password` (**secret** in Pulumi state), `-ses-smtp-host`
(`email-smtp.<region>.amazonaws.com`), `-ses-smtp-port` (`587`, STARTTLS),
`-ses-region` and `-ses-iam-user`. When `region` matches the provider's
region the password is the provider's `aws.iam.AccessKey.sesSmtpPasswordV4`;
otherwise the plugin derives it for `region` with the same documented
algorithm.

A consuming stack reads them through `uses:` exactly like an `s3-bucket`:

```yaml
# .sc/stacks/mautic-innmind/client.yaml
stacks:
  prod:
    type: cloud-compose
    parent: alphamind-co/alphamind-co
    config:
      uses: [mautic-ses]
      env:
        MAUTIC_MAILER_HOST: ${resource:mautic-ses.smtp-host}
        MAUTIC_MAILER_PORT: ${resource:mautic-ses.smtp-port}
      secrets:
        MAUTIC_MAILER_USER: ${resource:mautic-ses.smtp-user}
        MAUTIC_MAILER_PASSWORD: ${resource:mautic-ses.smtp-password}
```

`${resource:<name>.…}` keys: `smtp-user`, `smtp-password`, `smtp-host`,
`smtp-port`, `region`, and `configuration-set` when configured. Put
`smtp-user` / `smtp-password` under `secrets:`, not `env:`: SC resolves the
placeholder in either section, and only `secrets:` stores the value as a
secret. The processor also injects `SMTP_<NAME>_HOST` / `_PORT` / `_USER` /
`_PASSWORD`, `SES_<NAME>_REGION` and unscoped `SMTP_HOST` / `SMTP_PORT` /
`SMTP_USER` / `SMTP_PASSWORD` / `SES_REGION` (never overriding an existing
value), where `<NAME>` is the env-suffixed resource name (`MAUTIC_SES__PROD`);
`_USER` and `_PASSWORD` are injected as secrets.

SC core discovers the type from this plugin's `Schema`, so no core change is
needed, but the parent stack must pin `plugins.aws` to a release that has it:
SC's auto-injection only recognises its built-in list of AWS types and
reports `unknown type "aws-ses-smtp-user"` without an explicit `plugins.aws`
block.

The access key is created once and is not rotated automatically. Rotating it
means replacing the `…-ses-smtp-access-key` resource in the parent stack and
then redeploying every consumer.
