// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"github.com/pkg/errors"
	"github.com/samber/lo"
)

// ValidateContainerSecrets checks allowlists against the running containers.
// A nil availableSecrets defers secret-name validation until compute resource
// secrets are known by the driver; a non-nil (even empty) list validates both.
func (i *EcsFargateInput) ValidateContainerSecrets(availableSecrets []string) error {
	if i.CloudExtras == nil {
		return nil
	}
	for container, names := range i.CloudExtras.ContainerSecrets {
		if !lo.ContainsBy(i.Containers, func(c EcsFargateContainer) bool { return c.Name == container }) {
			return errors.Errorf("cloudExtras.containerSecrets: unknown container %q (must be in runs)", container)
		}
		if availableSecrets == nil {
			continue
		}
		for _, name := range names {
			if !lo.Contains(availableSecrets, name) {
				return errors.Errorf("cloudExtras.containerSecrets[%q]: unknown secret %q", container, name)
			}
		}
	}
	return nil
}
