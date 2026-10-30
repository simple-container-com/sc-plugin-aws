// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"context"

	"github.com/pkg/errors"

	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/internals"

	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	scPlugin "github.com/simple-container-com/api/pkg/plugin"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
)

// scCoreRegistrar is the plugin-side bridge from an AWS driver that
// calls `params.Registrar.*` to the registrar plugin that actually
// owns DNS (cloudflare, cloudru-dns, yc-dns). Each method routes
// through SC core's SCCore.PeerInvoke endpoint — the host receives
// our call, looks the target plugin up in its loaded-plugins
// registry, and dispatches the matching SCCloudPlugin RPC. D8 of
// 06-decisions.md: a direct plugin-to-plugin connection was rejected
// in favour of this broker pattern.
//
// Fields are set per-Provision call from fields the sidecar packs
// into ProvisionRequest (RegistrarPluginName / RegistrarType /
// RegistrarMainDomain). Zero-valued when the deploying stack has no
// registrar.
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

// NewRecord resolves record.Value in THIS plugin's pctx (an output can
// cross our own pctx fine) and PeerInvokes NewDnsRecord on the
// registrar plugin.
func (r *scCoreRegistrar) NewRecord(ctx *sdk.Context, record api.DnsRecord) (*api.ResourceOutput, error) {
	req := &scpluginv1.NewDnsRecordRequest{
		Header:        r.cloneHeader(),
		RegistrarType: r.typeToken,
		RecordName:    record.Name,
		RecordType:    record.Type,
		ValueResolved: record.Value,
		Proxied:       record.Proxied,
	}
	resp, err := r.peer.NewDnsRecord(ctx.Context(), r.pluginName, req)
	if err != nil {
		return nil, errors.Wrapf(err, "scCoreRegistrar.NewRecord via PeerInvoke to %q", r.pluginName)
	}
	return &api.ResourceOutput{Ref: resp.GetUrn()}, nil
}

func (r *scCoreRegistrar) NewOverrideHeaderRule(ctx *sdk.Context, stack api.Stack, rule pApi.OverrideHeaderRule) (*api.ResourceOutput, error) {
	toHost, err := awaitStringInput(ctx.Context(), rule.ToHost)
	if err != nil {
		return nil, errors.Wrap(err, "scCoreRegistrar.NewOverrideHeaderRule: resolve ToHost")
	}
	req := &scpluginv1.NewOverrideHeaderRuleRequest{
		Header:         r.cloneHeader(),
		RegistrarType:  r.typeToken,
		StackName:      stack.Name,
		RuleName:       rule.Name,
		FromHost:       rule.FromHost,
		ToHostResolved: toHost,
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
		return nil, errors.Wrapf(err, "scCoreRegistrar.NewOverrideHeaderRule via PeerInvoke to %q", r.pluginName)
	}
	return &api.ResourceOutput{Ref: resp.GetUrn()}, nil
}

func (r *scCoreRegistrar) ProvisionDomainForEndpoint(ctx *sdk.Context, stack api.Stack, endpoint pApi.DomainEndpoint) (*api.ResourceOutput, error) {
	targetHost, err := awaitStringInput(ctx.Context(), endpoint.TargetHost)
	if err != nil {
		return nil, errors.Wrap(err, "scCoreRegistrar.ProvisionDomainForEndpoint: resolve TargetHost")
	}
	req := &scpluginv1.ProvisionDomainForEndpointRequest{
		Header:             r.cloneHeader(),
		RegistrarType:      r.typeToken,
		StackName:          stack.Name,
		EndpointName:       endpoint.Name,
		Domain:             endpoint.Domain,
		TargetHostResolved: targetHost,
		Websocket:          endpoint.WebSocket,
	}
	resp, err := r.peer.ProvisionDomainForEndpoint(ctx.Context(), r.pluginName, req)
	if err != nil {
		return nil, errors.Wrapf(err, "scCoreRegistrar.ProvisionDomainForEndpoint via PeerInvoke to %q", r.pluginName)
	}
	return &api.ResourceOutput{Ref: resp.GetUrn()}, nil
}

// cloneHeader returns a header for the proxied RPC, preserving the
// stack / env / project context the caller had but letting SC core
// re-stamp its own monitor/engine addresses when it dispatches the
// peer plugin.
func (r *scCoreRegistrar) cloneHeader() *scpluginv1.RequestHeader {
	if r.header == nil {
		return &scpluginv1.RequestHeader{}
	}
	return &scpluginv1.RequestHeader{
		StackName:   r.header.GetStackName(),
		ProjectName: r.header.GetProjectName(),
		Environment: r.header.GetEnvironment(),
	}
}

// awaitStringInput resolves an sdk.StringInput to a plain string by
// going through its ApplyT; sdk.StringOutput can be resolved inside the
// plugin's own pctx because the output was created there.
// internals.UnsafeAwaitOutput is used (the same path pkg/plugin/authoring.go
// uses — safer than the `ApplyT + channel` dance under preview).
func awaitStringInput(ctx context.Context, in sdk.StringInput) (string, error) {
	if in == nil {
		return "", nil
	}
	out := in.ToStringOutput()
	res, err := internals.UnsafeAwaitOutput(ctx, out)
	if err != nil {
		return "", err
	}
	if res.Value == nil {
		return "", nil
	}
	if s, ok := res.Value.(string); ok {
		return s, nil
	}
	return "", errors.Errorf("awaitStringInput: expected string, got %T", res.Value)
}
