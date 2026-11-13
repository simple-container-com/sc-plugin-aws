// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/simple-container-com/api/pkg/api"
)

// applyComponentRawToSingleImage overlays SC-Components fields from the raw map
// onto a StackConfigSingleImage. Called by any template whose ProvisionFunc
// accepts Component dispatch — today aws-lambda; ecs-fargate is the next to
// wire. The map comes from api core's slice 1a.1 side-channel
// (`input.ComponentRaw`); see sc-components-platform design doc §#19 path (b)
// and api PR #601.
//
// Known keys on the raw map (matching api.ComponentConfig accessors):
//
//   - "image"        — string (pre-built ref) OR map{dockerfile, context, build.args}.
//     String form sets Image.Name only (pulumi-docker treats the name as the
//     tag reference). Map form becomes a full ContainerImage with its build
//     block — this is the fleet-canonical shape every forge-* service uses to
//     trigger SC's image-build-and-push to ECR at deploy time.
//   - "env"          — map[string]string merged into cfg.Env (component values
//     win on key collision; operator's template-declared env entries are
//     otherwise preserved).
//   - "ingress.hostname"  — string → cfg.Domain.
//   - "ingress.registrar" — ignored at this layer; the top-level sidecar
//     wrapper is responsible for registrar selection via the parent's
//     registrars block. Noted here so a future per-component registrar
//     override has a slot to fill.
//   - "signingKey"   — string of shape `${secret:<alias>}` → injected as
//     SERVICE_JWT_SECRET under cfg.Secrets, so the deployed Component service
//     can verify the HS256 JWTs the plugin mints at ComputeProcess time.
//     Preserves the fleet convention: secrets go to cfg.Secrets, which the
//     Lambda provisioner wires to a per-function SecretsManager secret (never
//     a plain env var at rest).
//   - "deployTo"     — ignored; already resolved by api core when it selected
//     this template's ProvisionFunc for dispatch.
//
// Returns typed errors on malformed shapes (string-vs-map confusion,
// non-string keys in env, etc.) — mirrors the api.ComponentConfig getters'
// contract.
func applyComponentRawToSingleImage(cfg *api.StackConfigSingleImage, raw map[string]any) error {
	if cfg == nil {
		return errors.New("nil *StackConfigSingleImage")
	}
	if raw == nil {
		return nil
	}

	// image: string → pre-built ref; map → full ContainerImage.
	if v, ok := raw["image"]; ok && v != nil {
		componentImageConfig, err := parseComponentImage(v)
		if err != nil {
			return errors.Wrap(err, "image")
		}
		// Operator-declared template config wins only on fields it set;
		// component image overlays into a nil Image slot or merges with an
		// empty one. A template that already carries a full Image is unusual
		// (operators normally declare it on the client stack) — preserve it
		// rather than silently overwrite, per the design-doc merge rule
		// "operator wins on compute shape".
		//
		// NOTE: the assignment on the next line sets
		// api.StackConfigSingleImage.Image — an SC CONFIG field, resolved into
		// a build-and-push step at provision time. It is NOT a runtime image
		// reference (lambda.FunctionArgs.ImageUri / ECS TaskDef Image), which
		// must always be a signed digest. The distinctive variable name is
		// what the deploy_image_ref_test lint's allowlist pins on.
		if cfg.Image == nil {
			cfg.Image = componentImageConfig
		} else {
			mergeImage(cfg.Image, componentImageConfig)
		}
	}

	// env: component's keys merged into cfg.Env (component wins on collision).
	if v, ok := raw["env"]; ok && v != nil {
		envMap, err := parseComponentStringMap(v, "env")
		if err != nil {
			return err
		}
		if cfg.Env == nil {
			cfg.Env = map[string]string{}
		}
		for k, val := range envMap {
			cfg.Env[k] = val
		}
	}

	// ingress.hostname → cfg.Domain. ingress.registrar is deliberately ignored
	// here; see the doc comment above.
	if v, ok := raw["ingress"]; ok && v != nil {
		ingress, ok := v.(map[string]any)
		if !ok {
			return errors.Errorf("ingress: want map, got %T", v)
		}
		if host, ok := ingress["hostname"]; ok && host != nil {
			s, ok := host.(string)
			if !ok {
				return errors.Errorf("ingress.hostname: want string, got %T", host)
			}
			cfg.Domain = s
		}
	}

	// signingKey → cfg.Secrets["SERVICE_JWT_SECRET"]. The value is a
	// ${secret:<alias>} reference string; SC resolves it at provision time.
	if v, ok := raw["signingKey"]; ok && v != nil {
		s, ok := v.(string)
		if !ok {
			return errors.Errorf("signingKey: want string, got %T", v)
		}
		if cfg.Secrets == nil {
			cfg.Secrets = map[string]string{}
		}
		// Preserve any operator-declared SERVICE_JWT_SECRET if present —
		// matches the ComputeContextCollector's "operator wins" precedence on
		// explicit secret-env declarations elsewhere in the fleet.
		if _, present := cfg.Secrets["SERVICE_JWT_SECRET"]; !present {
			cfg.Secrets["SERVICE_JWT_SECRET"] = s
		}
	}

	// storage + metadata (generic Component config blocks → env):
	// slice 1e.4g.2 of sc-components-platform. Any Component may
	// declare top-level `storage:` / `metadata:` blocks in server.yaml;
	// this overlay translates each sub-field into a conventional env
	// entry so the deployed service reads its backend selection from
	// env without the operator having to duplicate values in `env:`.
	//
	// Convention: `<block>.<field>` → `<BLOCK_UPPER>_<FIELD_UPPER>`.
	// `storage.type: s3` → env `STORAGE_TYPE=s3`.
	// `metadata.uri: ${secret:...}` → env `METADATA_URI=${secret:...}`.
	//
	// Precedence: an explicit `env:` entry wins over a block-derived
	// entry. Operators who want to override a specific field just set
	// the env; the block-derived entries fill the slots the env didn't
	// already set.
	//
	// Scope: ONLY top-level map-valued blocks whose fields are string-
	// shaped. Nested maps / lists / numbers are not translated (operators
	// who need richer shapes can still write env: directly). Bools serialise
	// as "true"/"false" — a common env idiom.
	for _, blockKey := range []string{"storage", "metadata"} {
		raw, ok := raw[blockKey].(map[string]any)
		if !ok || raw == nil {
			continue
		}
		if cfg.Env == nil {
			cfg.Env = map[string]string{}
		}
		for k, val := range raw {
			envKey := blockToEnvKey(blockKey, k)
			if _, present := cfg.Env[envKey]; present {
				continue // explicit env: wins
			}
			strVal, ok := scalarToString(val)
			if !ok {
				continue // skip non-scalar sub-fields (nested shapes are advisory)
			}
			cfg.Env[envKey] = strVal
		}
	}

	// cloudExtras: per-key merge onto cfg.CloudExtras. cfg.CloudExtras is
	// typed `*any` on the SC-core side (an opaque container; aws-lambda's
	// provisioner later ConvertDescriptor's it into a typed *aws.CloudExtras).
	// So the overlay works at the map level, not the struct level.
	//
	// Merge rules match the design doc's "operator wins on compute shape":
	//   - SCALAR keys (e.g. lambdaRoutingType, lambdaInvokeMode, bools): if
	//     the operator already set the key, keep it; otherwise take the
	//     component's.
	//   - LIST keys (lambdaSchedules, awsRoles): APPEND-merge — operator's
	//     entries first (preserving ordering), then component's. A backup
	//     Component declaring one schedule + an operator declaring one
	//     schedule produces a Lambda with two schedules, not one or the
	//     other. awsRoles follow the same logic — a role list is additive.
	//
	// The list-key allowlist is maintained by name here because `*any` has
	// no type information to discriminate from. Adding a new list-typed
	// field to aws.CloudExtras MUST add its JSON tag to cloudExtrasListKeys
	// below, or the overlay will treat it as a scalar and operator-wins
	// will silently drop the component's contribution. That's a per-struct
	// trap worth flagging in review when aws.CloudExtras grows.
	if v, ok := raw["cloudExtras"]; ok && v != nil {
		if err := mergeComponentCloudExtras(cfg, v); err != nil {
			return errors.Wrap(err, "cloudExtras")
		}
	}

	return nil
}

// cloudExtrasListKeys names the JSON keys on aws.CloudExtras that are
// list-typed, keyed by the wire-level name (JSON tag). The overlay uses
// this set to pick APPEND-merge semantics over operator-wins for those
// keys. See the per-struct-trap note above `mergeComponentCloudExtras`'s
// caller — adding a new list field to aws.CloudExtras without adding its
// name here silently drops the component's contribution.
var cloudExtrasListKeys = map[string]bool{
	"lambdaSchedules": true,
	"awsRoles":        true,
}

func mergeComponentCloudExtras(cfg *api.StackConfigSingleImage, raw any) error {
	comp, ok := raw.(map[string]any)
	if !ok {
		return errors.Errorf("want map, got %T", raw)
	}
	// Normalise cfg.CloudExtras to a map we can mutate. nil → fresh map;
	// an existing *any pointing to a map → use its map; any other shape
	// is an operator-authored non-map (ints, strings, structs) which is
	// a config bug SC core would have caught earlier — reject rather
	// than silently drop it.
	var opMap map[string]any
	if cfg.CloudExtras != nil {
		switch existing := (*cfg.CloudExtras).(type) {
		case map[string]any:
			opMap = existing
		case nil:
			opMap = map[string]any{}
		default:
			return errors.Errorf("cfg.CloudExtras is %T, expected map or nil", existing)
		}
	} else {
		opMap = map[string]any{}
	}
	for k, cv := range comp {
		if cloudExtrasListKeys[k] {
			// APPEND-merge: existing list first (may be nil), component's
			// list appended. Empty-list-from-component is a no-op, not an
			// erase.
			compList, ok := cv.([]any)
			if !ok {
				return errors.Errorf("%s: want list, got %T", k, cv)
			}
			existing, _ := opMap[k].([]any)
			if len(compList) == 0 {
				// Preserve the existing list (if any) when the component
				// contributes nothing to a list field. Explicitly avoids
				// writing a non-nil empty []any into a previously-nil slot
				// (an operator reading the deploy's rendered state would
				// see a present-but-empty key where they declared nothing).
				continue
			}
			opMap[k] = append(existing, compList...)
		} else {
			// Operator wins on scalars: only fill the slot if operator
			// hasn't. A scalar-shaped collision where both operator and
			// component wrote the same key means the operator's value
			// stays, even if the component's was different.
			if _, present := opMap[k]; !present {
				opMap[k] = cv
			}
		}
	}
	// Re-pack as *any. Even if opMap came in via cfg.CloudExtras's existing
	// pointer, we re-assign to make the ownership explicit — the component
	// overlay is a merge, not a shared-reference mutation.
	asAny := any(opMap)
	cfg.CloudExtras = &asAny
	return nil
}

func parseComponentImage(v any) (*api.ContainerImage, error) {
	switch typed := v.(type) {
	case string:
		// Pre-built ref: no dockerfile, no build block. The Name slot is where
		// pulumi-docker reads the tag reference from downstream.
		return &api.ContainerImage{Name: typed}, nil
	case map[string]any:
		img := &api.ContainerImage{}
		if s, ok := typed["dockerfile"].(string); ok {
			img.Dockerfile = s
		}
		if s, ok := typed["context"].(string); ok {
			img.Context = s
		}
		if s, ok := typed["name"].(string); ok {
			img.Name = s
		}
		if bv, ok := typed["build"]; ok && bv != nil {
			bm, ok := bv.(map[string]any)
			if !ok {
				return nil, errors.Errorf("image.build: want map, got %T", bv)
			}
			img.Build = &api.ContainerImageBuild{Args: map[string]string{}}
			if av, ok := bm["args"]; ok && av != nil {
				argMap, err := parseComponentStringMap(av, "image.build.args")
				if err != nil {
					return nil, err
				}
				img.Build.Args = argMap
			}
		}
		return img, nil
	default:
		return nil, errors.Errorf("image: want string or map, got %T", v)
	}
}

// mergeImage overlays the component's image fields onto the operator-declared
// image. The rule matches the top-level "operator wins on compute shape,
// component wins on image/env" guidance from the design doc — but here both
// sides are supplying image bits, so we take the component's values for each
// non-zero field it set, leaving the operator's values intact where the
// component didn't override.
func mergeImage(dst, src *api.ContainerImage) {
	if src == nil {
		return
	}
	if src.Dockerfile != "" {
		dst.Dockerfile = src.Dockerfile
	}
	if src.Context != "" {
		dst.Context = src.Context
	}
	if src.Name != "" {
		dst.Name = src.Name
	}
	if src.Build != nil {
		if dst.Build == nil {
			dst.Build = &api.ContainerImageBuild{Args: map[string]string{}}
		}
		if dst.Build.Args == nil {
			dst.Build.Args = map[string]string{}
		}
		for k, v := range src.Build.Args {
			dst.Build.Args[k] = v
		}
	}
}

func parseComponentStringMap(v any, field string) (map[string]string, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.Errorf("%s: want map, got %T", field, v)
	}
	out := map[string]string{}
	for k, val := range m {
		s, ok := val.(string)
		if !ok {
			return nil, errors.Errorf("%s[%q]: want string, got %T", field, k, val)
		}
		out[k] = s
	}
	return out, nil
}

// blockToEnvKey turns a (blockName, fieldName) pair into the
// conventional env variable name. `storage`, `type` → `STORAGE_TYPE`.
// `metadata`, `sqlitePath` → `METADATA_SQLITE_PATH`. CamelCase fields
// split on upper-case boundaries so operators who write `accessKey:`
// end up with ACCESS_KEY, not ACCESSKEY.
//
// Slice 1e.4g.2 of sc-components-platform.
func blockToEnvKey(block, field string) string {
	var b strings.Builder
	b.Grow(len(block) + len(field) + 8)
	for i := 0; i < len(block); i++ {
		c := block[i]
		if c >= 'A' && c <= 'Z' && i > 0 {
			b.WriteByte('_')
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b.WriteByte(c)
	}
	b.WriteByte('_')
	for i := 0; i < len(field); i++ {
		c := field[i]
		if c >= 'A' && c <= 'Z' && i > 0 {
			b.WriteByte('_')
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// scalarToString serialises a scalar JSON-decoded value to a string
// an env var can carry. Returns ok=false for non-scalar shapes (maps,
// lists) — the overlay skips those so nested config blocks stay
// advisory (operator must write them in `env:` explicitly if the
// service needs them).
func scalarToString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case int:
		return fmt.Sprintf("%d", x), true
	case int64:
		return fmt.Sprintf("%d", x), true
	case float64:
		// YAML decoders emit numbers as float64; preserve integer shape
		// when round-tripping fits.
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x)), true
		}
		return fmt.Sprintf("%g", x), true
	default:
		return "", false
	}
}
