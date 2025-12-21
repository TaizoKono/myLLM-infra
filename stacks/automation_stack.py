from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_autoscaling as autoscaling,
    aws_events as events,
    aws_events_targets as targets,
    Duration,
)
from constructs import Construct


class AutomationStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        vpc: ec2.IVpc,
        auto_scaling_group: autoscaling.AutoScalingGroup,
        elastic_ip: ec2.CfnEIP,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        eip_attach_role = iam.Role(
            self,
            "EIPAttachLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
        )

        eip_attach_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeAddresses",
                    "ec2:AssociateAddress",
                    "ec2:DescribeInstances",
                ],
                resources=["*"],
            )
        )

        eip_attach_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "autoscaling:CompleteLifecycleAction",
                ],
                resources=[
                    f"arn:aws:autoscaling:{self.region}:{self.account}:autoScalingGroup:*:autoScalingGroupName/{auto_scaling_group.auto_scaling_group_name}",
                ],
            )
        )

        eip_attach_function = lambda_.Function(
            self,
            "EIPAttachFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda_functions/eip_attach"),
            role=eip_attach_role,
            timeout=Duration.seconds(60),
            environment={
                "EIP_ALLOCATION_ID": elastic_ip.attr_allocation_id,
            },
        )

        wireguard_restore_role = iam.Role(
            self,
            "WireGuardRestoreLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
            ],
        )

        wireguard_restore_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                ],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/private-key",
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/public-key",
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/peer-public-key",
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/server-address",
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/peer-address",
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/peer-allowed-ips",
                ],
            )
        )

        wireguard_restore_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ssm:SendCommand",
                    "ssm:GetCommandInvocation",
                ],
                resources=["*"],
            )
        )

        wireguard_restore_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeInstances",
                ],
                resources=["*"],
            )
        )

        wireguard_restore_function = lambda_.Function(
            self,
            "WireGuardRestoreFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda_functions/wireguard_restore"),
            role=wireguard_restore_role,
            timeout=Duration.seconds(300),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
        )

        asg_event_rule = events.Rule(
            self,
            "ASGLifecycleEventRule",
            event_pattern=events.EventPattern(
                source=["aws.autoscaling"],
                detail_type=["EC2 Instance-launch Lifecycle Action"],
                detail={
                    "AutoScalingGroupName": [auto_scaling_group.auto_scaling_group_name],
                },
            ),
        )

        asg_event_rule.add_target(targets.LambdaFunction(eip_attach_function))

        # Lambda function to update route tables
        route_update_role = iam.Role(
            self,
            "RouteUpdateLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
        )

        route_update_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeInstances",
                    "ec2:DescribeRouteTables",
                    "ec2:CreateRoute",
                    "ec2:ReplaceRoute",
                    "ec2:DeleteRoute",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:ModifyInstanceAttribute",
                ],
                resources=["*"],
            )
        )

        route_update_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "autoscaling:CompleteLifecycleAction",
                ],
                resources=[
                    f"arn:aws:autoscaling:{self.region}:{self.account}:autoScalingGroup:*:autoScalingGroupName/{auto_scaling_group.auto_scaling_group_name}",
                ],
            )
        )

        route_update_function = lambda_.Function(
            self,
            "RouteUpdateFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda_functions/route_update"),
            role=route_update_role,
            timeout=Duration.seconds(60),
            environment={
                "VPC_ID": vpc.vpc_id,
                "VPN_CIDR": "10.200.0.0/24",
            },
        )

        asg_event_rule.add_target(targets.LambdaFunction(route_update_function))
