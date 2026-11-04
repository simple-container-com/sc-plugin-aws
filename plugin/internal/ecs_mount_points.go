// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"github.com/pkg/errors"

	clouds "github.com/simple-container-com/sc-plugin-aws/api"
)

// validateEcsMountPoints rejects a task definition ECS would refuse anyway,
// before any Pulumi resource is registered. Every mount point needs a
// container path and a source volume that is one of the stack's declared
// volumes (the EFS-backed task volumes built from crInput.Volumes).
//
// Without this guard an empty SourceVolume (e.g. a mount point that lost its
// fields crossing the plugin bus) only surfaced as an
// ECS `ClientException: Unknown volume` (empty name) after secrets, EFS file systems and
// mount targets had already been created.
func validateEcsMountPoints(input *clouds.EcsFargateInput) error {
	volumes := make(map[string]struct{}, len(input.Volumes))
	for _, v := range input.Volumes {
		volumes[v.Name] = struct{}{}
	}
	for _, c := range input.Containers {
		for i, mp := range c.MountPoints {
			switch {
			case mp.SourceVolume == "":
				return errors.Errorf("container %q mount point #%d (containerPath %q) has an empty sourceVolume", c.Name, i, mp.ContainerPath)
			case mp.ContainerPath == "":
				return errors.Errorf("container %q mount point #%d (sourceVolume %q) has an empty containerPath", c.Name, i, mp.SourceVolume)
			}
			if _, ok := volumes[mp.SourceVolume]; !ok {
				return errors.Errorf("container %q mount point #%d references volume %q, which is not among the stack's volumes", c.Name, i, mp.SourceVolume)
			}
		}
	}
	return nil
}
