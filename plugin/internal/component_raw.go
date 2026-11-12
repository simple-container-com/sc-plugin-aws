// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
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
