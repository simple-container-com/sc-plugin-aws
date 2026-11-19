// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/simple-container-com/api/pkg/api"
)

// TestBuildBundlePayload_MergesBothSources pins the contract that the
// bundle gathers from BOTH `contextSecrets` (compute-context secret
// envs) and `stackSecrets` (the `.sc/stacks/<stack>/secrets.yaml`
// `values:` registry), so bundle mode is a drop-in for the legacy
// per-key path in `aws_lambda.go:189-204`.
func TestBuildBundlePayload_MergesBothSources(t *testing.T) {
	ctxVars := []secretValue{
		{Name: "TAVILY_API_KEY", Value: "tvly-xxx"},
		{Name: "RESEND_API_KEY", Value: "re_yyy"},
	}
	stackSecrets := map[string]string{
		"STRIPE_WEBHOOK_SECRET": "whsec_zzz",
	}

	got := buildBundlePayload(ctxVars, stackSecrets)

	assert.Equal(t, "tvly-xxx", got["TAVILY_API_KEY"])
	assert.Equal(t, "re_yyy", got["RESEND_API_KEY"])
	assert.Equal(t, "whsec_zzz", got["STRIPE_WEBHOOK_SECRET"])
	assert.Len(t, got, 3)
}

// TestBuildBundlePayload_StackSecretsWinOnCollision — context secrets
// come first, stack secrets apply second. If both source the same key,
// the stack secret value wins. (Mirrors the legacy per-key order:
// context secrets are built first, then stackConfig.Secrets, so the
// second write would overwrite in a map build.)
func TestBuildBundlePayload_StackSecretsWinOnCollision(t *testing.T) {
	ctxVars := []secretValue{
		{Name: "KEY", Value: "from-context"},
	}
	stackSecrets := map[string]string{
		"KEY": "from-stack",
	}
	got := buildBundlePayload(ctxVars, stackSecrets)
	assert.Equal(t, "from-stack", got["KEY"])
}

// TestBuildBundlePayload_EmptyInputs — nil + nil = empty map. Guard
// against a surprise nil-dereference when a service has no secrets at
// all but still opts into bundle mode (which is a valid-if-pointless
// configuration — the Pulumi side still builds a Secret, just an
// empty JSON object).
func TestBuildBundlePayload_EmptyInputs(t *testing.T) {
	got := buildBundlePayload(nil, nil)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

// TestBuildBundlePayload_SerialisesStably — the JSON key order is
// deterministic across deploys (json.Marshal sorts map keys), which
// keeps the SecretVersion diff tight when nothing changed. Protects
// against a future developer swapping json.Marshal for something that
// doesn't sort.
func TestBuildBundlePayload_SerialisesStably(t *testing.T) {
	payload := buildBundlePayload(
		[]secretValue{{Name: "B", Value: "2"}, {Name: "A", Value: "1"}},
		map[string]string{"C": "3"},
	)
	raw, err := json.Marshal(payload)
	assert.NoError(t, err)
	assert.Equal(t, `{"A":"1","B":"2","C":"3"}`, string(raw))
}

// TestBundleSecretName_IgnoresDeployVersion is the guard for a rename
// that would otherwise happen on EVERY deploy.
//
// The bundle secret's name suffix is the OPERATOR's `config.version` —
// documented as "only when need to forcefully redeploy (e.g. aws
// secrets)" and normally empty — matching the per-key secrets in
// aws_lambda.go. It used to be deployParams.Version, the CalVer deploy
// version, which is a different field that changes on every deploy.
//
// Dormant only because the deploy version never reached a plugin (the
// bus carried no version field until api#640). The moment it did,
// forge-conductor's deploy failed:
//
//	destructive delete by rename: preview would DELETE 1 live resource(s)
//	  …Secret::forge-conductor--staging--bundle----secrets would be DELETED;
//	  the plan creates …--bundle----secrets2026.11.19-713bb2e instead
//
// Pulumi matches by name, so that is an independent create plus a
// delete of the live secret — not a replace the engine reconciles.
func TestBundleSecretName_IgnoresDeployVersion(t *testing.T) {
	params := api.StackParams{
		StackName:   "forge-conductor",
		Environment: "staging",
		// A deploy version is present on every CI deploy now.
		Version: "2026.11.19-713bb2e",
	}

	// No operator config.version → stable name across deploys.
	stable := toSecretName(params, "bundle", "", "secrets", "")
	if strings.Contains(stable, "2026.11.19") {
		t.Errorf("name %q embeds the deploy version — it would rename on every deploy", stable)
	}

	// Two different deploy versions must produce the SAME name.
	params2 := params
	params2.Version = "2026.11.20-aaaaaaa"
	if other := toSecretName(params2, "bundle", "", "secrets", ""); other != stable {
		t.Errorf("name changed with the deploy version: %q vs %q", stable, other)
	}

	// The operator's own knob still rotates it — that is its purpose.
	rotated := toSecretName(params, "bundle", "", "secrets", "v2")
	if rotated == stable {
		t.Error("config.version did not change the name; the force-rotate knob is dead")
	}
}
