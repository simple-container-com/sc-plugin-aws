// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/types"
	"github.com/stretchr/testify/require"

	"github.com/simple-container-com/api/pkg/api"
	"github.com/simple-container-com/api/pkg/clouds/compose"
	awsApi "github.com/simple-container-com/sc-plugin-aws/api"
)

// Regression for alphamind-blog's ECS deploy failing with
// `ClientException: Unknown volume` (empty name): EcsFargateMountPoint had no json/yaml
// tags, core JSON-encoded it as {"ContainerPath":..,"SourceVolume":..} and the
// plugin's yaml decode looked for lowercased keys, so every mount point
// arrived empty. The compose shape mirrors the blog stack.
func TestDecodeTypedConfig_EcsMountPointsSurviveBus(t *testing.T) {
	project := &types.Project{
		WorkingDir: "/offline",
		Volumes: types.Volumes{
			"mariadb-data":        types.VolumeConfig{},
			"alphamind-blog-data": types.VolumeConfig{},
		},
		Services: types.Services{
			{
				Name: "mariadb", Image: "mariadb:11", Ports: []types.ServicePortConfig{{Target: 3306}},
				Volumes: []types.ServiceVolumeConfig{{Type: types.VolumeTypeVolume, Source: "mariadb-data", Target: "/var/lib/mysql"}},
			},
			{
				Name: "blog", Image: "ghost:5", Ports: []types.ServicePortConfig{{Target: 2368}},
				Volumes: []types.ServiceVolumeConfig{{Type: types.VolumeTypeVolume, Source: "alphamind-blog-data", Target: "/var/lib/ghost/content"}},
			},
			{
				Name: "caddy", Image: "caddy:2",
				Labels: map[string]string{api.ComposeLabelIngressContainer: "true"},
				Ports:  []types.ServicePortConfig{{Target: 80}},
			},
		},
	}
	converted, err := awsApi.ToEcsFargateConfig(&awsApi.TemplateConfig{}, compose.Config{Project: project}, &api.StackConfigCompose{
		Runs: []string{"mariadb", "blog", "caddy"},
	})
	require.NoError(t, err)

	// Encode exactly as SC core does (json.Marshal -> InputValue tree),
	// decode exactly as the plugin's Provision path does.
	decoded, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, converted))
	require.NoError(t, err)
	in := decoded.(*awsApi.EcsFargateInput)

	mounts := map[string][]awsApi.EcsFargateMountPoint{}
	for _, c := range in.Containers {
		mounts[c.Name] = c.MountPoints
	}
	require.Equal(t, []awsApi.EcsFargateMountPoint{{SourceVolume: "mariadb-data", ContainerPath: "/var/lib/mysql"}}, mounts["mariadb"])
	require.Equal(t, []awsApi.EcsFargateMountPoint{{SourceVolume: "alphamind-blog-data", ContainerPath: "/var/lib/ghost/content"}}, mounts["blog"])
	require.Contains(t, mounts, "caddy")
	require.Empty(t, mounts["caddy"])
	require.ElementsMatch(t, []awsApi.EcsFargateVolume{{Name: "mariadb-data"}, {Name: "alphamind-blog-data"}}, in.Volumes)
	require.Equal(t, "caddy", in.IngressContainer.Name)
}

// Round-trip guard: every field of a fully populated EcsFargateInput must
// survive core's JSON encoding and the plugin's decode. A new untagged or
// mis-tagged field anywhere in the tree fails here instead of in a deploy.
func TestDecodeTypedConfig_EcsFargateInputRoundTrip(t *testing.T) {
	want := &awsApi.EcsFargateInput{}
	fillAll(reflect.ValueOf(want).Elem(), "in", 0)
	// StackConfig.CloudExtras is the raw client block decodeTypedConfig
	// re-applies onto CloudExtras; leave it empty so the comparison is a
	// pure transport check.
	want.StackConfig.CloudExtras = nil

	decoded, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, want))
	require.NoError(t, err)
	require.Equal(t, want, decoded.(*awsApi.EcsFargateInput))
}

// fillAll sets every exported field reachable from v to a distinct non-zero
// value. Fields JSON never carries (`json:"-"`) and `any` fields are skipped.
func fillAll(v reflect.Value, path string, depth int) {
	if depth > 12 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(path)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(len(path)%100) + 1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(len(path)%100) + 1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(len(path)%100) + 0.5)
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		fillAll(v.Elem(), path, depth+1)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillAll(s.Index(0), path+"[0]", depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		k := reflect.New(v.Type().Key()).Elem()
		fillAll(k, path+".key", depth+1)
		e := reflect.New(v.Type().Elem()).Elem()
		fillAll(e, path+".val", depth+1)
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() || strings.HasPrefix(f.Tag.Get("json"), "-") {
				continue
			}
			fillAll(v.Field(i), fmt.Sprintf("%s.%s", path, f.Name), depth+1)
		}
	}
}
