// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	"github.com/stretchr/testify/require"

	clouds "github.com/simple-container-com/sc-plugin-aws/api"
)

func mountPointsInput(mps ...clouds.EcsFargateMountPoint) *clouds.EcsFargateInput {
	return &clouds.EcsFargateInput{
		Volumes: []clouds.EcsFargateVolume{{Name: "mariadb-data"}, {Name: "alphamind-blog-data"}},
		Containers: []clouds.EcsFargateContainer{
			{Name: "mariadb", MountPoints: mps},
			{Name: "blog", MountPoints: []clouds.EcsFargateMountPoint{{SourceVolume: "alphamind-blog-data", ContainerPath: "/var/lib/ghost/content"}}},
			{Name: "caddy"},
		},
	}
}

func TestValidateEcsMountPoints(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		require.NoError(t, validateEcsMountPoints(mountPointsInput(clouds.EcsFargateMountPoint{SourceVolume: "mariadb-data", ContainerPath: "/var/lib/mysql"})))
	})
	t.Run("no volumes, no mounts", func(t *testing.T) {
		require.NoError(t, validateEcsMountPoints(&clouds.EcsFargateInput{Containers: []clouds.EcsFargateContainer{{Name: "web"}}}))
	})
	t.Run("empty sourceVolume", func(t *testing.T) {
		err := validateEcsMountPoints(mountPointsInput(clouds.EcsFargateMountPoint{ContainerPath: "/var/lib/mysql"}))
		require.ErrorContains(t, err, `container "mariadb"`)
		require.ErrorContains(t, err, "empty sourceVolume")
	})
	t.Run("fully empty mount point (lost on the bus)", func(t *testing.T) {
		require.ErrorContains(t, validateEcsMountPoints(mountPointsInput(clouds.EcsFargateMountPoint{})), "empty sourceVolume")
	})
	t.Run("empty containerPath", func(t *testing.T) {
		require.ErrorContains(t, validateEcsMountPoints(mountPointsInput(clouds.EcsFargateMountPoint{SourceVolume: "mariadb-data"})), "empty containerPath")
	})
	t.Run("unknown volume", func(t *testing.T) {
		err := validateEcsMountPoints(mountPointsInput(clouds.EcsFargateMountPoint{SourceVolume: "nope", ContainerPath: "/data"}))
		require.ErrorContains(t, err, `references volume "nope"`)
	})
}
