// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

// Golden builder copied from origin/main (3ecb573), with only its name changed.
import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	ecsV6 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ecs"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/efs"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	lbV6 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/lb"
	"github.com/pulumi/pulumi-awsx/sdk/v2/go/awsx/awsx"
	"github.com/pulumi/pulumi-awsx/sdk/v2/go/awsx/ecs"
	"github.com/pulumi/pulumi-awsx/sdk/v2/go/awsx/lb"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/samber/lo"
	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	taggingUtil "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	"github.com/simple-container-com/api/pkg/util"
	"github.com/simple-container-com/sc-plugin-aws/api"
	"strconv"
	"strings"
	"time"
)

func originMainEcsFargateCluster(ctx *sdk.Context, stack api.Stack, params pApi.ProvisionParams, deployParams api.StackParams, crInput *aws.EcsFargateInput, ref *EcsFargateOutput) error {
	opts := []sdk.ResourceOption{
		sdk.Provider(params.Provider),
		sdk.DependsOn(params.ComputeContext.Dependencies()),
	}

	// Build unified tags using the tagging utility
	tags := taggingUtil.BuildTagsFromStackParams(deployParams).ToAWSTags()

	// Gate every resource in this cluster on the image security operations.
	// The nil guard matches the export loop further down and the Kubernetes
	// path's imageSecurityOpts: MapErr can leave a nil entry in ref.Images, and
	// the two loops disagreeing about that is how one of them panics.
	for _, img := range ref.Images {
		if img == nil {
			continue
		}
		opts = append(opts, img.AddOpts...)
	}

	iContainer := crInput.IngressContainer

	contextSecretEnvVariables := lo.Filter(params.ComputeContext.SecretEnvVariables(), func(s pApi.ComputeEnvVariable, _ int) bool {
		return crInput.Secrets[s.Name] == ""
	})
	contextEnvVariables := params.ComputeContext.EnvVariables()

	var secrets []*CreatedSecret
	ctxSecrets, err := util.MapErr(contextSecretEnvVariables, func(v pApi.ComputeEnvVariable, _ int) (*CreatedSecret, error) {
		return createSecret(ctx, toSecretName(deployParams, v.ResourceType, v.ResourceName, v.Name, crInput.Config.Version), v.Name, v.Value, tags, opts...)
	})
	if err != nil {
		return errors.Wrapf(err, "failed to create context secrets for stack %q in %q", stack.Name, deployParams.Environment)
	}
	secrets = append(secrets, ctxSecrets...)
	for name, value := range crInput.Secrets {
		s, err := createSecret(ctx, toSecretName(deployParams, "values", "", name, crInput.Config.Version), name, value, tags, opts...)
		if err != nil {
			return errors.Wrapf(err, "failed to create secret")
		}
		secrets = append(secrets, s)
	}
	params.Log.Info(ctx.Context(), "configure secrets in SecretsManager for %d secrets in stack %q in %q...", len(secrets), stack.Name, deployParams.Environment)
	ref.Secrets = secrets

	ecsSimpleClusterName := fmt.Sprintf("%s-%s", stack.Name, deployParams.Environment)

	var vpcID sdk.IDOutput
	var publicSubnets defaultSubnets
	var privateSubnets defaultSubnets

	if lo.FromPtr(lo.FromPtr(crInput.StackConfig).StaticEgressIP) {
		params.Log.Info(ctx.Context(), "configure static egress IP for VPC of ECS cluster %s...", ecsSimpleClusterName)
		egressOut, err := provisionStaticEgressForMultiZoneVpc(ctx, ecsSimpleClusterName, &StaticEgressIPIn{
			Params:        params,
			Provider:      params.Provider,
			AccountConfig: crInput.AccountConfig,
			StackParams:   deployParams,
		}, opts...)
		if err != nil {
			return errors.Wrapf(err, "failed to create static egress IP for ECS cluster %q", ecsSimpleClusterName)
		}
		vpcID = egressOut.VPC.ID()
		publicSubnets = ToSubnets(egressOut.Subnets.PublicSubnets())
		privateSubnets = ToSubnets(egressOut.Subnets.PrivateSubnets())
	} else {
		publicSubnets, err = createDefaultSubnetsInRegionV5(ctx, crInput.AccountConfig, deployParams.Environment, params)
		if err != nil {
			return errors.Wrapf(err, "failed to get or create default subnets in region")
		}
		params.Log.Info(ctx.Context(), "found %d default subnets in region %s", len(privateSubnets), crInput.AccountConfig.Region)
		privateSubnets = publicSubnets

		// Create a new VPC for our ECS tasks.
		params.Log.Info(ctx.Context(), "configure VPC for ECS cluster %s...", ecsSimpleClusterName)
		vpcName := fmt.Sprintf("%s-vpc", ecsSimpleClusterName)
		vpc, err := ec2.NewDefaultVpc(ctx, vpcName, nil, opts...)
		if err != nil {
			return errors.Wrapf(err, "failed to create default vpc for ECS cluster %q", ecsSimpleClusterName)
		}
		vpcID = vpc.ID()
	}
	opts = append(opts, sdk.DependsOn(privateSubnets.Resources()))

	params.Log.Info(ctx.Context(), "configure security group for ECS cluster %s...", ecsSimpleClusterName)
	securityGroupName := fmt.Sprintf("%s-sg", ecsSimpleClusterName)
	ingressTCPSGArgs := ec2.SecurityGroupIngressArgs{
		Description:    sdk.String("Allow ALL inbound traffic"),
		Protocol:       sdk.String("tcp"),
		FromPort:       sdk.Int(0),
		ToPort:         sdk.Int(65535),
		CidrBlocks:     sdk.StringArray{sdk.String("0.0.0.0/0")},
		Ipv6CidrBlocks: sdk.StringArray{sdk.String("::/0")},
	}
	if crInput.CloudExtras != nil && crInput.CloudExtras.SecurityGroup != nil {
		ingressTCPSGArgs, err = processIngressSGArgs(&ingressTCPSGArgs, *crInput.CloudExtras.SecurityGroup, publicSubnets)
		if err != nil {
			return errors.Wrapf(err, "failed to apply security group configuration from cloud extras for ECS cluster %q", ecsSimpleClusterName)
		}
	}
	securityGroup, err := ec2.NewSecurityGroup(ctx, securityGroupName, &ec2.SecurityGroupArgs{
		VpcId: vpcID,
		Tags:  tags,
		Ingress: ec2.SecurityGroupIngressArray{
			&ingressTCPSGArgs,
		},
		Egress: ec2.SecurityGroupEgressArray{
			&ec2.SecurityGroupEgressArgs{
				Description:    sdk.String("Allow ALL outbound TCP traffic"),
				Protocol:       sdk.String("tcp"),
				FromPort:       sdk.Int(0),
				ToPort:         sdk.Int(65535),
				CidrBlocks:     sdk.StringArray{sdk.String("0.0.0.0/0")},
				Ipv6CidrBlocks: sdk.StringArray{sdk.String("::/0")},
			},
			// UDP egress is required for any workload that needs STUN
			// reflexive-candidate discovery or direct UDP media (WebRTC,
			// VoIP, QUIC without ALPN, etc). Without this rule, pion's
			// ICE agent can't reach STUN servers, no srflx candidate
			// is gathered, and the only remaining path is a TURN-TCP-TLS
			// relay — which routes correctly but is a well-known
			// SFU-side anti-abuse trigger that silently withholds
			// returning media on some bridges. Live-caught 2026-10-08
			// in forge-baas ktalk: a Kontur.Talk JVB forwarded zero
			// RTP to any Fargate-origin participant until this rule
			// landed. Opening UDP 0-65535 is standard for Fargate
			// services; stateful SG tracks the per-flow mapping, so
			// return-direction UDP is auto-allowed without an ingress
			// rule.
			&ec2.SecurityGroupEgressArgs{
				Description:    sdk.String("Allow ALL outbound UDP traffic (WebRTC/STUN/VoIP)"),
				Protocol:       sdk.String("udp"),
				FromPort:       sdk.Int(0),
				ToPort:         sdk.Int(65535),
				CidrBlocks:     sdk.StringArray{sdk.String("0.0.0.0/0")},
				Ipv6CidrBlocks: sdk.StringArray{sdk.String("::/0")},
			},
			&ec2.SecurityGroupEgressArgs{
				Description:    sdk.String("Allow NFS outbound traffic"),
				Protocol:       sdk.String("tcp"),
				FromPort:       sdk.Int(2049),
				ToPort:         sdk.Int(2049),
				CidrBlocks:     sdk.StringArray{sdk.String("0.0.0.0/0")},
				Ipv6CidrBlocks: sdk.StringArray{sdk.String("::/0")},
			},
		},
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to crate security group for ECS cluster %q", ecsSimpleClusterName)
	}

	// Create an ECS task execution IAM role
	roleName := fmt.Sprintf("%s-exec-role", ecsSimpleClusterName)
	taskExecRole, err := iam.NewRole(ctx, roleName, &iam.RoleArgs{
		Name:                sdk.String(ecsSimpleClusterName),
		Tags:                tags,
		PermissionsBoundary: permissionsBoundaryPtr(crInput.AccountConfig.PermissionsBoundary),
		AssumeRolePolicy: sdk.String(`{
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ecs-tasks.amazonaws.com"
                    }
                }]
            }`),
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create IAM role for stack %q in %q", stack.Name, deployParams.Environment)
	}
	ref.ExecRole = taskExecRole
	ctx.Export(fmt.Sprintf("%s-exec-role-arn", ecsSimpleClusterName), taskExecRole.Arn)

	var volumes ecsV6.TaskDefinitionVolumeArray
	for _, v := range crInput.Volumes {
		efsName := fmt.Sprintf("%s-%s-fs", ecsSimpleClusterName, v.Name)
		params.Log.Info(ctx.Context(), "configure efs file system %s for volume %s...", efsName, v.Name)
		fs, err := efs.NewFileSystem(ctx, efsName, &efs.FileSystemArgs{
			Tags: tags,
		}, opts...)
		if err != nil {
			return errors.Wrapf(err, "failed to create file system for persistent volume %s of stack %s", v.Name, stack.Name)
		}
		_, err = efs.NewBackupPolicy(ctx, efsName, &efs.BackupPolicyArgs{
			BackupPolicy: efs.BackupPolicyBackupPolicyArgs{
				Status: sdk.String("ENABLED"),
			},
			FileSystemId: fs.ID(),
		}, opts...)
		if err != nil {
			return errors.Wrapf(err, "failed to create EFS backup policy for volume %s of stack %s", v.Name, stack.Name)
		}

		_, err = util.MapErr(privateSubnets, func(subnet Subnet, i int) (*efs.MountTarget, error) {
			mountTargetName := fmt.Sprintf("%s-%s-mt-%d", ecsSimpleClusterName, v.Name, i)
			params.Log.Info(ctx.Context(), "configure mount target %s for volume %s for efs...", mountTargetName, v.Name)
			return efs.NewMountTarget(ctx, mountTargetName, &efs.MountTargetArgs{
				FileSystemId: fs.ID(),
				SubnetId:     subnet.id,
				SecurityGroups: sdk.StringArray{
					securityGroup.ID(),
				},
			}, opts...)
		})
		if err != nil {
			return errors.Wrapf(err, "failed to create mount targets for efs %s for volume %s of stack %s", efsName, v.Name, stack.Name)
		}
		volumes = append(volumes, ecsV6.TaskDefinitionVolumeArgs{
			Name: sdk.String(v.Name),
			EfsVolumeConfiguration: ecsV6.TaskDefinitionVolumeEfsVolumeConfigurationArgs{
				FileSystemId:      fs.ID(),
				RootDirectory:     sdk.String("/"),
				TransitEncryption: sdk.String("ENABLED"),
				AuthorizationConfig: ecsV6.TaskDefinitionVolumeEfsVolumeConfigurationAuthorizationConfigArgs{
					Iam: sdk.String("ENABLED"),
				},
			},
		})
	}
	logGroupName := fmt.Sprintf("/ecs/%s", ecsSimpleClusterName)
	containers := lo.MapValues(lo.GroupBy(lo.Map(
		ref.Images,
		func(image *ECRImage, index int) EcsContainerDef {
			hostPort := image.Container.Port
			envVariables := ecs.TaskDefinitionKeyValuePairArray{}
			for k := range lo.Assign(image.Container.Env) {
				if _, found := lo.Find(secrets, func(s *CreatedSecret) bool {
					return s.EnvVar == k
				}); found {
					delete(image.Container.Env, k)
				}
			}
			ctxEnvVariables := lo.Filter(contextEnvVariables, func(v pApi.ComputeEnvVariable, _ int) bool {
				return image.Container.Env[v.Name] == ""
			})
			envVariables = append(envVariables, lo.Map(ctxEnvVariables, func(e pApi.ComputeEnvVariable, _ int) ecs.TaskDefinitionKeyValuePairInput {
				return ecs.TaskDefinitionKeyValuePairArgs{
					Name:  sdk.StringPtr(e.Name),
					Value: sdk.StringPtr(e.Value),
				}
			})...)
			envVariables = append(envVariables, lo.MapToSlice(image.Container.Env, func(key string, value string) ecs.TaskDefinitionKeyValuePairInput {
				return ecs.TaskDefinitionKeyValuePairArgs{
					Name:  sdk.StringPtr(key),
					Value: sdk.StringPtr(value),
				}
			})...)
			envVariables = append(envVariables, lo.Map(lo.Entries(params.BaseEnvVariables), func(e lo.Entry[string, string], index int) ecs.TaskDefinitionKeyValuePairInput {
				return ecs.TaskDefinitionKeyValuePairArgs{
					Name:  sdk.StringPtr(e.Key),
					Value: sdk.StringPtr(e.Value),
				}
			})...)
			envVariables = append(envVariables, ecs.TaskDefinitionKeyValuePairArgs{
				Name:  sdk.StringPtr(api.ComputeEnv.StackVersion),
				Value: sdk.StringPtr(deployParams.Version),
			})
			secretsVariables := ecs.TaskDefinitionSecretArray{}
			secretsVariables = append(secretsVariables, lo.Map(secrets, func(item *CreatedSecret, _ int) ecs.TaskDefinitionSecretInput {
				return ecs.TaskDefinitionSecretArgs{
					Name:      sdk.String(item.EnvVar),
					ValueFrom: item.Secret.Arn,
				}
			})...)

			var mountPoints ecs.TaskDefinitionMountPointArray
			lo.ForEach(image.Container.MountPoints, func(v aws.EcsFargateMountPoint, _ int) {
				mountPoints = append(mountPoints, ecs.TaskDefinitionMountPointArgs{
					ContainerPath: sdk.String(v.ContainerPath),
					ReadOnly:      sdk.BoolPtr(v.ReadOnly),
					SourceVolume:  sdk.String(v.SourceVolume),
				})
			})
			cpu := lo.If(image.Container.Cpu == 0, 256).Else(image.Container.Cpu)

			var dependsOn ecs.TaskDefinitionContainerDependencyArray
			lo.ForEach(lo.Filter(image.Container.DependsOn,
				func(d aws.EcsFargateDependsOn, _ int) bool {
					return lo.Contains(
						lo.Map(crInput.Containers, func(c aws.EcsFargateContainer, _ int) string {
							return c.Name
						}), d.Container,
					)
				}),
				func(dep aws.EcsFargateDependsOn, _ int) {
					dependsOn = append(dependsOn, ecs.TaskDefinitionContainerDependencyArgs{
						Condition:     sdk.String(dep.Condition),
						ContainerName: sdk.String(dep.Container),
					})
				})
			memory := lo.If(image.Container.Memory == 0, 512).Else(image.Container.Memory)
			cDef := EcsContainerDef{
				TaskDefinitionContainerDefinitionArgs: ecs.TaskDefinitionContainerDefinitionArgs{
					Name:        sdk.String(image.Container.Name),
					Image:       image.DeployImageRef,
					Cpu:         sdk.IntPtr(cpu),
					Memory:      sdk.IntPtr(memory),
					Essential:   sdk.BoolPtr(true),
					Environment: envVariables,
					Secrets:     secretsVariables,
					MountPoints: mountPoints,
					DependsOn:   dependsOn,
					LogConfiguration: ecs.TaskDefinitionLogConfigurationArgs{
						LogDriver: sdk.String("awslogs"),
						Options: sdk.StringMap{
							"awslogs-create-group":  sdk.String("true"),
							"awslogs-group":         sdk.String(logGroupName),
							"awslogs-region":        sdk.String(crInput.Config.Region),
							"awslogs-stream-prefix": sdk.String("ecs"),
						},
						// `secretOptions` is omitted since it's null in the provided configuration.
					},
					PortMappings: ecs.TaskDefinitionPortMappingArray{
						ecs.TaskDefinitionPortMappingArgs{
							ContainerPort: sdk.IntPtr(image.Container.Port),
							HostPort:      sdk.IntPtr(hostPort),
						},
					},
				},
				Name: image.Container.Name,
			}
			liveProbe := image.Container.LivenessProbe
			if liveProbe.HttpGet.Port != 0 {
				// TODO
			} else if len(liveProbe.Command) > 0 {
				cDef.HealthCheck = ecs.TaskDefinitionHealthCheckArgs{
					Command:     sdk.ToStringArray(liveProbe.Command),
					Interval:    sdk.IntPtr(lo.If(liveProbe.IntervalSeconds > 0, liveProbe.IntervalSeconds).Else(10)),
					Retries:     sdk.IntPtr(lo.If(liveProbe.Retries > 0, liveProbe.Retries).Else(10)),
					StartPeriod: sdk.IntPtr(liveProbe.InitialDelaySeconds),
					Timeout:     sdk.IntPtr(lo.If(liveProbe.TimeoutSeconds > 2, liveProbe.TimeoutSeconds).Else(30)),
				}
			}
			return cDef
		},
	),
		func(container EcsContainerDef) string {
			return container.Name
		}),
		func(value []EcsContainerDef, key string) ecs.TaskDefinitionContainerDefinitionArgs {
			return value[0].TaskDefinitionContainerDefinitionArgs
		})

	lbType := aws.LoadBalancerTypeAlb

	if lo.FromPtr(crInput.CloudExtras).LoadBalancerType != "" {
		lbType = lo.FromPtr(crInput.CloudExtras).LoadBalancerType
	}

	var ecsLoadBalancers ecsV6.ServiceLoadBalancerArrayInput
	var applicationLoadBalancer *lb.ApplicationLoadBalancer

	if lbType == aws.LoadBalancerTypeAlb {
		params.Log.Info(ctx.Context(), "configure application loadbalancer for %q in %q...", stack.Name, deployParams.Environment)
		loadBalancerName := util.TrimStringMiddle(fmt.Sprintf("%s-%s-alb%s", stack.Name, deployParams.Environment, crInput.Config.Version), 30, "-")
		targetGroupName := util.TrimStringMiddle(fmt.Sprintf("%s-%s-tg%s", stack.Name, deployParams.Environment, crInput.Config.Version), 30, "-")

		var lbHC *lbV6.TargetGroupHealthCheckArgs
		liveProbe := iContainer.LivenessProbe
		lbHC = &lbV6.TargetGroupHealthCheckArgs{
			Port:               sdk.StringPtr(lo.If(liveProbe.HttpGet.Port > 0, strconv.Itoa(liveProbe.HttpGet.Port)).Else(strconv.Itoa(iContainer.Port))),
			Path:               sdk.StringPtr(lo.If(liveProbe.HttpGet.Path != "", liveProbe.HttpGet.Path).Else("/")),
			Matcher:            sdk.StringPtr(lo.If(liveProbe.HttpGet.SuccessCodes != "", liveProbe.HttpGet.SuccessCodes).Else("200")),
			Timeout:            sdk.IntPtr(lo.If(liveProbe.TimeoutSeconds > 2, liveProbe.TimeoutSeconds).Else(6)),
			Interval:           sdk.IntPtr(lo.If(liveProbe.IntervalSeconds > 0, liveProbe.IntervalSeconds).Else(30)),
			HealthyThreshold:   sdk.IntPtr(lo.If(liveProbe.HttpGet.HealthyThreshold > 0, liveProbe.HttpGet.HealthyThreshold).Else(3)),
			UnhealthyThreshold: sdk.IntPtr(lo.If(liveProbe.Retries > 0, liveProbe.Retries).Else(3)),
		}
		applicationLoadBalancer, err = lb.NewApplicationLoadBalancer(ctx, loadBalancerName, &lb.ApplicationLoadBalancerArgs{
			Name:      sdk.String(loadBalancerName),
			Tags:      tags,
			SubnetIds: publicSubnets.Ids(),
			DefaultTargetGroup: &lb.TargetGroupArgs{
				Name:        sdk.String(targetGroupName),
				HealthCheck: lbHC,
			},
			SecurityGroups: sdk.StringArray{securityGroup.ID()},
		}, opts...)
		if err != nil {
			return errors.Wrapf(err, "failed to create application loadbalancer for %q in %q", stack.Name, deployParams.Environment)
		}
		ref.LoadBalancerDNSHost = lo.ToPtr(applicationLoadBalancer.LoadBalancer.DnsName())
		ctx.Export(fmt.Sprintf("%s-alb-arn", ecsSimpleClusterName), applicationLoadBalancer.LoadBalancer.Arn())
		ctx.Export(fmt.Sprintf("%s-alb-name", ecsSimpleClusterName), applicationLoadBalancer.LoadBalancer.Name())

		ecsLoadBalancers = ecsV6.ServiceLoadBalancerArray{
			ecsV6.ServiceLoadBalancerArgs{
				ContainerName:  sdk.String(iContainer.Name),
				ContainerPort:  sdk.Int(iContainer.Port),
				TargetGroupArn: applicationLoadBalancer.DefaultTargetGroup.Arn(),
			},
		}
	} else if lbType == aws.LoadBalancerTypeNlb {
		// Create a Network Load Balancer
		loadBalancerName := util.TrimStringMiddle(fmt.Sprintf("%s-%s-nlb%s", stack.Name, deployParams.Environment, crInput.Config.Version), 23, "-")
		targetGroupName := util.TrimStringMiddle(fmt.Sprintf("%s-%s-tg%s", stack.Name, deployParams.Environment, crInput.Config.Version), 23, "-")

		nlb, err := lbV6.NewLoadBalancer(ctx, loadBalancerName, &lbV6.LoadBalancerArgs{
			Subnets:          publicSubnets.Ids(),
			Tags:             tags,
			LoadBalancerType: sdk.String("network"),
		}, opts...)
		if err != nil {
			return errors.Wrapf(err, "failed to create network loadbalancer for %q in %q", stack.Name, deployParams.Environment)
		}

		targetGroup, err := lbV6.NewTargetGroup(ctx, targetGroupName, &lbV6.TargetGroupArgs{
			Name:       nlb.Name,
			Port:       sdk.Int(80),
			Protocol:   sdk.String("TCP"),
			TargetType: sdk.String("ip"),
			VpcId:      vpcID,
			Tags:       tags,
		}, append(opts, sdk.DeleteBeforeReplace(true))...)
		if err != nil {
			return errors.Wrapf(err, "failed to create target group for %q in %q", stack.Name, deployParams.Environment)
		}

		// Create a NLB target group attachment to replace if the NLB changes
		_, err = lbV6.NewListener(ctx, fmt.Sprintf("%s-attachment", targetGroupName), &lbV6.ListenerArgs{
			LoadBalancerArn: nlb.Arn,
			Tags:            tags,
			Port:            sdk.Int(80),
			Protocol:        sdk.String("TCP"),
			DefaultActions: lbV6.ListenerDefaultActionArray{
				&lbV6.ListenerDefaultActionArgs{
					Type:           sdk.String("forward"),
					TargetGroupArn: targetGroup.Arn,
				},
			},
		}, append(opts, sdk.DeleteBeforeReplace(true))...)
		if err != nil {
			return errors.Wrapf(err, "failed to create target group attachment for %q in %q", stack.Name, deployParams.Environment)
		}

		ecsLoadBalancers = ecsV6.ServiceLoadBalancerArray{
			ecsV6.ServiceLoadBalancerArgs{
				ContainerName:  sdk.String(iContainer.Name),
				ContainerPort:  sdk.Int(iContainer.Port),
				TargetGroupArn: targetGroup.Arn,
			},
		}
		ref.LoadBalancerDNSHost = lo.ToPtr(nlb.DnsName)
	}

	params.Log.Info(ctx.Context(), "configure ECS Fargate cluster for %q in %q with ingress container %q...",
		stack.Name, deployParams.Environment, iContainer.Name)
	ecsClusterName := awsResName(ecsSimpleClusterName, "cluster")
	cluster, err := ecsV6.NewCluster(ctx, ecsSimpleClusterName, &ecsV6.ClusterArgs{
		Name: sdk.String(ecsClusterName),
		Tags: tags,
		Configuration: ecsV6.ClusterConfigurationArgs{
			ExecuteCommandConfiguration: ecsV6.ClusterConfigurationExecuteCommandConfigurationArgs{
				Logging: sdk.String("DEFAULT"),
			},
		},
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create ECS cluster for %q in %q", stack.Name, deployParams.Environment)
	}
	ref.Cluster = cluster
	ctx.Export(fmt.Sprintf("%s-arn", ecsSimpleClusterName), cluster.Arn)
	ctx.Export(fmt.Sprintf("%s-name", ecsSimpleClusterName), cluster.Name)

	awsCloudExtras := &aws.CloudExtras{}
	if crInput.CloudExtras != nil {
		var err error
		awsCloudExtras, err = api.ConvertDescriptor(crInput.CloudExtras, awsCloudExtras)
		if err != nil {
			return errors.Wrapf(err, "failed to convert cloudExtras field to AWS Cloud extras format")
		}
	}
	policyActions := []string{
		"ssm:StartSession",
		"ssmmessages:CreateControlChannel",
		"ssmmessages:CreateDataChannel",
		"ssmmessages:OpenControlChannel",
		"ssmmessages:OpenDataChannel",
		"secretsmanager:GetSecretValue",
		"ecr:GetAuthorizationToken",
		"ecr:DescribeImages",
		"ecr:DescribeRepositories",
		"ecr:BatchGetImage",
		"ecr:BatchCheckLayerAvailability",
		"ecr:GetDownloadUrlForLayer",
		"logs:CreateLogStream",
		"logs:CreateLogGroup",
		"logs:DescribeLogStreams",
		"logs:PutLogEvents",
		"elasticfilesystem:ClientMount",
		"elasticfilesystem:ClientWrite",
		"elasticfilesystem:DescribeMountTargets",
		"elasticfilesystem:DescribeFileSystems",
		"cloudwatch:PutMetricData",
	}

	params.Log.Info(ctx.Context(), "adding extra roles %q for lambda %q...", strings.Join(awsCloudExtras.AwsRoles, ","), stack.Name)
	policyActions = append(policyActions, awsCloudExtras.AwsRoles...)

	ccPolicyName := fmt.Sprintf("%s-policy", ecsSimpleClusterName)
	ccPolicy, err := iam.NewPolicy(ctx, ccPolicyName, &iam.PolicyArgs{
		Description: sdk.String("Allows CreateControlChannel operation and reading secrets"),
		Name:        sdk.String(ccPolicyName),
		Tags:        tags,
		Policy: sdk.All().ApplyT(func(args []interface{}) (sdk.StringOutput, error) {
			policy := map[string]interface{}{
				"Version": "2012-10-17",
				"Statement": []map[string]any{
					{
						"Effect":   "Allow",
						"Resource": "*",
						"Action":   policyActions,
					},
				},
			}
			policyJSON, err := json.Marshal(policy)
			if err != nil {
				return sdk.StringOutput{}, err
			}
			return sdk.String(policyJSON).ToStringOutput(), nil
		}).(sdk.StringOutput),
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create policy for stack %q in %q", stack.Name, deployParams.Environment)
	}
	ref.Policy = ccPolicy
	ctx.Export(fmt.Sprintf("%s-policy", ecsSimpleClusterName), ccPolicy.Arn)

	params.Log.Info(ctx.Context(), "configure Fargate service for %q in %q with ingress container %q...",
		stack.Name, deployParams.Environment, iContainer.Name)
	ecsServiceName := awsResName(ecsSimpleClusterName, "svc")
	service, err := ecs.NewFargateService(ctx, fmt.Sprintf("%s-service", ecsSimpleClusterName), &ecs.FargateServiceArgs{
		Cluster:                         cluster.Arn,
		Name:                            sdk.String(ecsServiceName),
		DesiredCount:                    sdk.Int(lo.If(crInput.Scale.Min == 0, 1).Else(crInput.Scale.Min)),
		DeploymentMaximumPercent:        sdk.IntPtr(lo.If(crInput.Scale.Update.MaxPercent == 0, 200).Else(crInput.Scale.Update.MaxPercent)),
		DeploymentMinimumHealthyPercent: sdk.IntPtr(lo.If(crInput.Scale.Update.MinHealthyPercent == 0, 100).Else(crInput.Scale.Update.MinHealthyPercent)),
		ContinueBeforeSteadyState:       sdk.BoolPtr(false),
		TaskDefinitionArgs: &ecs.FargateServiceTaskDefinitionArgs{
			Family: sdk.String(fmt.Sprintf("%s-%s", stack.Name, deployParams.Environment)),
			Cpu:    sdk.String(lo.If(crInput.Config.Cpu == 0, "256").Else(strconv.Itoa(crInput.Config.Cpu))),
			Memory: sdk.String(lo.If(crInput.Config.Memory == 0, "512").Else(strconv.Itoa(crInput.Config.Memory))),
			EphemeralStorage: lo.If[ecsV6.TaskDefinitionEphemeralStoragePtrInput](crInput.Config.EphemeralStorageGB == 0, nil).
				Else(&ecsV6.TaskDefinitionEphemeralStorageArgs{
					SizeInGib: sdk.Int(crInput.Config.EphemeralStorageGB),
				}),
			Containers: containers,
			Volumes:    volumes,
			ExecutionRole: &awsx.DefaultRoleWithPolicyArgs{
				RoleArn: taskExecRole.Arn,
			},
			TaskRole: &awsx.DefaultRoleWithPolicyArgs{
				RoleArn: taskExecRole.Arn,
			},
		},
		ForceNewDeployment:   sdk.BoolPtr(true),
		EnableExecuteCommand: sdk.BoolPtr(true),
		Tags: func() sdk.StringMap {
			serviceTags := sdk.StringMap{
				"deployTime": sdk.String(time.Now().Format(time.RFC3339)),
			}
			for k, v := range tags {
				serviceTags[k] = v
			}
			return serviceTags
		}(),
		NetworkConfiguration: ecsV6.ServiceNetworkConfigurationArgs{
			AssignPublicIp: sdk.BoolPtr(true),
			SecurityGroups: sdk.StringArray{
				securityGroup.ID(),
			},
			Subnets: privateSubnets.Ids(),
		},
		LoadBalancers: ecsLoadBalancers,
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create ecs service for stack %q in %q", stack.Name, deployParams.Environment)
	}
	ref.Service = service
	ctx.Export(fmt.Sprintf("%s-service-name", ecsSimpleClusterName), service.Service.Name())

	// Attach the service's generated policy to the task role. The ECS Fargate
	// task definition above binds BOTH ExecutionRole and TaskRole to the same
	// `taskExecRole` — the running container's AWS SDK and ECS's secret-pull
	// path reach the actions through the one attachment below. There is only
	// one role, one policy, one attachment.
	//
	// A second attachment was previously created inside a nested
	// `service.TaskDefinition.ApplyT(...).ApplyT(...)` closure for the same
	// (role, policy) pair. Pulumi treats resources instantiated inside a
	// nested Apply closure as deferred creates whose outputs aren't registered
	// into the resource graph, so each `pulumi up` would call `DetachRolePolicy`
	// on the previous iteration's attachment (because the parent
	// `service.TaskDefinition` churns on the `deployTime` tag — set on every
	// deploy, line ~679) without a paired `AttachRolePolicy` being tracked.
	// Net effect: the role ended every deploy with the policy detached, new
	// tasks failed to start with `AccessDeniedException` on
	// `secretsmanager:GetSecretValue`, and the running task kept serving
	// traffic only until its STS credentials expired. Live-caught on
	// baas-meeting staging after forge-baas added `cloudExtras.awsRoles` for
	// the first time (2026-10-06; CloudTrail entry at 18:42:48 UTC).
	execPolicyAttachmentName := fmt.Sprintf("%s-p-exec", ecsSimpleClusterName)
	execPolicyAttachment, err := iam.NewRolePolicyAttachment(ctx, execPolicyAttachmentName, &iam.RolePolicyAttachmentArgs{
		Role:      taskExecRole.Name,
		PolicyArn: ccPolicy.Arn,
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create policy attachment stack %q in %q", stack.Name, deployParams.Environment)
	}
	ref.ExecPolicyAttachment = execPolicyAttachment
	ctx.Export(fmt.Sprintf("%s-p-exec-arn", ecsSimpleClusterName), execPolicyAttachment.PolicyArn)

	params.Log.Info(ctx.Context(), "configure Cloudwatch dashboard for ecs cluster %q...", ecsClusterName)
	if err := createEcsCloudwatchDashboard(ctx, ecsCloudwatchDashboardCfg{
		ecsClusterName: ecsClusterName,
		ecsServiceName: ecsServiceName,
		logGroupName:   logGroupName,
		stackName:      stack.Name,
		region:         crInput.Region,
	}, params); err != nil {
		return errors.Wrapf(err, "failed to create ECS cw dashboard")
	}

	if crInput.Scale.Policies != nil {
		err = attachAutoScalingPolicy(ctx, stack, params, crInput, cluster, service, tags)
		if err != nil {
			return errors.Wrapf(err, "failed to attach auto scaling policy to service %q/%q", ecsSimpleClusterName, fmt.Sprintf("%s-service", ecsSimpleClusterName))
		}
	}

	if crInput.Alerts != nil {
		cluster.Name.ApplyT(func(clusterName string) any {
			return createEcsAlerts(ctx, clusterName, ecsServiceName, stack, crInput, deployParams, params, applicationLoadBalancer, opts...)
		})
	}
	return nil
}
