// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"runtime/debug"

	"github.com/pkg/errors"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	scPlugin "github.com/simple-container-com/api/pkg/plugin"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
)

// recoverApplyT converts a panic inside an ApplyT closure into a returned
// error carrying the message AND the stack. Pulumi SDK **v3.245.0** (the
// version this plugin's `plugin/go.mod` currently pins) does NOT recover
// panics in `ApplyT` continuations — grep for `recover(` in
// pulumi/sdk/v3@v3.245.0/go/{internal,pulumi}/*.go returns zero hits.
// This can change in a later SDK; if you upgrade the pin, re-grep before
// deciding this wrapper is redundant.
//
// With the current SDK: a panic inside an ApplyT closure takes the plugin
// process down with Go's unrecovered-panic exit status 2, and the trace
// lands on raw stderr — which `go-plugin` forwards at `hclog.Debug` and
// SC core currently drops at its `hclog.Warn` filter (api PR #522 raises
// that).
//
// The visible symptom until both ends are fixed:
//
//	plugin process exited: … error="exit status 2"
//	Provision("…"): rpc error: code = Unavailable desc = error reading from server: EOF
//
// — with no information about which closure panicked or why. Wrapping
// each ApplyT body in `defer recoverApplyT(&err, name)` turns that into
// a normal Pulumi error carried back through the Output chain, with the
// panic value and the stack preserved in the message.
//
// `name` is the registrar method label so a crash in one ApplyT doesn't
// read as a crash in another.
func recoverApplyT(err *error, name string) {
	if r := recover(); r != nil {
		*err = errors.Errorf("panic in %s ApplyT: %v\n%s", name, r, debug.Stack())
	}
}

// scCoreRegistrar is the plugin-side bridge from an AWS driver that
// calls `params.Registrar.*` to the registrar plugin that actually
// owns DNS (cloudflare, cloudru-dns, yc-dns). Each method routes
// through SC core's SCCore.PeerInvoke endpoint — the host receives
// our call, looks the target plugin up in its loaded-plugins
// registry, and dispatches the matching SCCloudPlugin RPC. D8 of
// 06-decisions.md: a direct plugin-to-plugin connection was rejected
// in favour of this broker pattern.
//
// Every sdk.StringInput that comes in flows through ApplyT so the
// Pulumi engine resolves it when it IS known — the alternative
// synchronous `internals.UnsafeAwaitOutput` deadlocks under preview
// because the Lambda Function URL is unknown until the Lambda is
// created.
type scCoreRegistrar struct {
	peer       *scPlugin.PeerClient
	pluginName string
	typeToken  string
	mainDomain string
	header     *scpluginv1.RequestHeader
}

func newSCCoreRegistrar(peer *scPlugin.PeerClient, header *scpluginv1.RequestHeader, pluginName, typeToken, mainDomain string) *scCoreRegistrar {
	return &scCoreRegistrar{
		peer:       peer,
		pluginName: pluginName,
		typeToken:  typeToken,
		mainDomain: mainDomain,
		header:     header,
	}
}

func (r *scCoreRegistrar) MainDomain() string { return r.mainDomain }

// ProvisionRecords is a no-op from this plugin's side — the registrar
// plugin's ProvisionRecords runs when SC core bootstraps the stack's
// registrar section, not when a client stack's resource is provisioned.
// A plugin whose driver calls params.Registrar.ProvisionRecords (none
// of the AWS drivers do) would need PeerInvoke(ProvisionRegistrar) first.
func (r *scCoreRegistrar) ProvisionRecords(_ *sdk.Context, _ pApi.ProvisionParams) (*api.ResourceOutput, error) {
	return &api.ResourceOutput{Ref: "plugin:scCoreRegistrar/ProvisionRecords:noop"}, nil
}

// NewRecord forwards the record to the registrar plugin. Driver call
// sites pass the CNAME target as `record.ValueOut` (an sdk.StringOutput)
// when it references a Pulumi output — ecs-fargate's
// `LoadBalancerDNSHost`, static-website's `WebsiteEndpoint`, s3-bucket's
// `BucketDomainName`. Only static records from server.yaml come in on
// `record.Value` directly, and no plugin-side driver takes that path
// today (grep: all four callers set `ValueOut`).
//
// Mirror the ApplyT shape used for `ProvisionDomainForEndpoint` so the
// resolved hostname reaches the registrar plugin at continuation time
// instead of empty-string at Provision time. Dropping to `record.Value`
// produced a `CNAME → ""` on every ecs-fargate / static-site deploy
// (ecs-fargate: run 41109940459, both forge-baas stacks, 2026-10-30).
//
// `record.Value` is folded in as a fallback — if a future call site
// hands us a plain string record from server.yaml it still routes
// correctly; the ApplyT on `ValueOut.ApplyT(...)` sees an empty string
// when ValueOut is zero-state, and we use `Value` instead.
func (r *scCoreRegistrar) NewRecord(ctx *sdk.Context, record api.DnsRecord) (*api.ResourceOutput, error) {
	urnOut := record.ValueOut.ApplyT(func(resolvedValue string) (urn string, err error) {
		defer recoverApplyT(&err, "NewRecord")
		if resolvedValue == "" {
			resolvedValue = record.Value
		}
		req := &scpluginv1.NewDnsRecordRequest{
			Header:        r.cloneHeader(),
			RegistrarType: r.typeToken,
			RecordName:    record.Name,
			RecordType:    record.Type,
			ValueResolved: resolvedValue,
			Proxied:       record.Proxied,
		}
		resp, err := r.peer.NewDnsRecord(ctx.Context(), r.pluginName, req)
		if err != nil {
			return "", errors.Wrapf(err, "scCoreRegistrar.NewRecord via PeerInvoke to %q", r.pluginName)
		}
		return resp.GetUrn(), nil
	})
	return &api.ResourceOutput{Ref: urnOut}, nil
}

func (r *scCoreRegistrar) NewOverrideHeaderRule(ctx *sdk.Context, stack api.Stack, rule pApi.OverrideHeaderRule) (*api.ResourceOutput, error) {
	toHost := rule.ToHost
	if toHost == nil {
		toHost = sdk.String("")
	}
	urnOut := toHost.ToStringOutput().ApplyT(func(resolvedToHost string) (urn string, err error) {
		defer recoverApplyT(&err, "NewOverrideHeaderRule")
		req := &scpluginv1.NewOverrideHeaderRuleRequest{
			Header:         r.cloneHeader(),
			RegistrarType:  r.typeToken,
			StackName:      stack.Name,
			RuleName:       rule.Name,
			FromHost:       rule.FromHost,
			ToHostResolved: resolvedToHost,
			PathPrefix:     rule.PathPrefix,
		}
		if rule.BasicAuth != nil {
			req.BasicAuth = &scpluginv1.BasicAuthMsg{
				Username: rule.BasicAuth.Username,
				Password: rule.BasicAuth.Password,
				Realm:    rule.BasicAuth.Realm,
			}
		}
		if rule.OverridePages != nil {
			req.OverridePages = &scpluginv1.OverridePagesMsg{
				IndexPage:    rule.OverridePages.IndexPage,
				NotFoundPage: rule.OverridePages.NotFoundPage,
			}
		}
		resp, err := r.peer.NewOverrideHeaderRule(ctx.Context(), r.pluginName, req)
		if err != nil {
			return "", errors.Wrapf(err, "scCoreRegistrar.NewOverrideHeaderRule via PeerInvoke to %q", r.pluginName)
		}
		return resp.GetUrn(), nil
	})
	return &api.ResourceOutput{Ref: urnOut}, nil
}

func (r *scCoreRegistrar) ProvisionDomainForEndpoint(ctx *sdk.Context, stack api.Stack, endpoint pApi.DomainEndpoint) (*api.ResourceOutput, error) {
	target := endpoint.TargetHost
	if target == nil {
		target = sdk.String("")
	}
	urnOut := target.ToStringOutput().ApplyT(func(resolvedTargetHost string) (urn string, err error) {
		defer recoverApplyT(&err, "ProvisionDomainForEndpoint")
		req := &scpluginv1.ProvisionDomainForEndpointRequest{
			Header:             r.cloneHeader(),
			RegistrarType:      r.typeToken,
			StackName:          stack.Name,
			EndpointName:       endpoint.Name,
			Domain:             endpoint.Domain,
			TargetHostResolved: resolvedTargetHost,
			Websocket:          endpoint.WebSocket,
		}
		resp, err := r.peer.ProvisionDomainForEndpoint(ctx.Context(), r.pluginName, req)
		if err != nil {
			return "", errors.Wrapf(err, "scCoreRegistrar.ProvisionDomainForEndpoint via PeerInvoke to %q", r.pluginName)
		}
		return resp.GetUrn(), nil
	})
	return &api.ResourceOutput{Ref: urnOut}, nil
}

// cloneHeader returns a header for the proxied RPC, preserving the
// stack / env / project context AND the monitor/engine addresses the
// caller received. The SC-core PeerInvoke dispatcher
// (pkg/clouds/pulumi/plugin_peer_dispatch.go DispatchPeer) forwards
// the request verbatim; it does NOT re-stamp monitor/engine addresses,
// and `Client.stampHeader` only fills `SccoreAddress` /
// `SccoreBrokerStream`. So if the aws plugin drops `MonitorAddress`
// here, the cloudflare plugin's `pulumiContextFromHeader` errors with
//
//	peer invoke cloudflare.NewDnsRecord: peer error: rpc error:
//	code = Unknown desc = no monitor address in request header
//
// and every AWS stack that calls `params.Registrar.NewRecord`
// (any `aws-lambda` / `ecs-fargate` / `aws-static-website` with a
// `domain:`) fails to provision. Live-caught on forge-baas 2026-10-30
// (run 41106953898), both `baas-meeting` and `browse`.
//
// The aws plugin's own `Provision` already received these fields on
// its request header; forwarding them is the one-line fix.
//
// Deliberately NOT forwarded: `SccoreAddress` / `SccoreBrokerStream`.
// Each spawned plugin has its own loopback SCCore listener
// (`pkg/plugin/client.go` "One listener per plugin"), and
// `Client.stampHeader` fills these ONLY if empty — so copying aws's
// value here would overwrite cloudflare's own, pointing cloudflare's
// callbacks at an sccore listener owned by aws's Client lifecycle.
// Harmless today (dispatch routes by plugin name), but the mechanism
// exists precisely so sidecars don't have to remember this.
func (r *scCoreRegistrar) cloneHeader() *scpluginv1.RequestHeader {
	if r.header == nil {
		return &scpluginv1.RequestHeader{}
	}
	return &scpluginv1.RequestHeader{
		MonitorAddress: r.header.GetMonitorAddress(),
		EngineAddress:  r.header.GetEngineAddress(),
		StackName:      r.header.GetStackName(),
		ProjectName:    r.header.GetProjectName(),
		Environment:    r.header.GetEnvironment(),
	}
}
