// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	clouds "github.com/simple-container-com/sc-plugin-aws/api"
)

// Validate before creating secrets or building images, including when an older
// core has not validated the new cloudExtras field during compose conversion.
func validateEcsContainerSecrets(input *clouds.EcsFargateInput, compute pApi.ComputeContext) error {
	if input.CloudExtras == nil || len(input.CloudExtras.ContainerSecrets) == 0 {
		return nil
	}
	available := make([]string, 0, len(input.Secrets))
	for name := range input.Secrets {
		available = append(available, name)
	}
	for _, v := range compute.SecretEnvVariables() {
		available = append(available, v.Name)
	}
	return input.ValidateContainerSecrets(available)
}
