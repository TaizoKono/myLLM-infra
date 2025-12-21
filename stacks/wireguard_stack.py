from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_autoscaling as autoscaling,
    aws_iam as iam,
    aws_ssm as ssm,
    aws_logs as logs,
    CfnOutput,
    Duration,
    Tags,
)
from constructs import Construct


class WireGuardStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        vpc: ec2.IVpc,
        wireguard_security_group: ec2.ISecurityGroup,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.elastic_ip = ec2.CfnEIP(
            self,
            "WireGuardEIP",
            tags=[{"key": "Name", "value": "WireGuardEIP"}],
        )

        # CloudWatch Logs group with retention period
        log_group = logs.LogGroup(
            self,
            "WireGuardLogGroup",
            log_group_name="/aws/ec2/wireguard",
            retention=logs.RetentionDays.THREE_MONTHS,
        )

        instance_role = iam.Role(
            self,
            "WireGuardInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                ),
            ],
        )

        instance_role.add_to_policy(
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

        instance_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeAddresses",
                    "ec2:AssociateAddress",
                ],
                resources=["*"],
            )
        )

        instance_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    log_group.log_group_arn + ":*",
                ],
            )
        )

        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "#!/bin/bash",
            "set -ex",
            "exec > >(tee /var/log/user-data.log) 2>&1",
            "",
            "echo 'Starting WireGuard setup...'",
            "",
            "# Update system",
            "dnf update -y",
            "",
            "# Install WireGuard",
            "dnf install -y wireguard-tools",
            "",
            "# Install CloudWatch Agent",
            "dnf install -y amazon-cloudwatch-agent",
            "",
            "# Enable IP forwarding",
            "cat >> /etc/sysctl.conf <<EOF",
            "net.ipv4.ip_forward = 1",
            "net.ipv4.conf.all.forwarding = 1",
            "EOF",
            "sysctl -p",
            "",
            "# Get WireGuard configuration from Parameter Store",
            f"PRIVATE_KEY=$(aws ssm get-parameter --name private-key --with-decryption --region {self.region} --query 'Parameter.Value' --output text)",
            f"PEER_PUBLIC_KEY=$(aws ssm get-parameter --name peer-public-key --region {self.region} --query 'Parameter.Value' --output text)",
            f"SERVER_ADDRESS=$(aws ssm get-parameter --name server-address --region {self.region} --query 'Parameter.Value' --output text)",
            f"PEER_ADDRESS=$(aws ssm get-parameter --name peer-address --region {self.region} --query 'Parameter.Value' --output text)",
            f"PEER_ALLOWED_IPS=$(aws ssm get-parameter --name peer-allowed-ips --region {self.region} --query 'Parameter.Value' --output text)",
            "",
            "# Create WireGuard configuration",
            "mkdir -p /etc/wireguard",
            "cat > /etc/wireguard/wg0.conf <<EOF",
            "[Interface]",
            "PrivateKey = $PRIVATE_KEY",
            "Address = $SERVER_ADDRESS",
            "ListenPort = 51820",
            "",
            "[Peer]",
            "PublicKey = $PEER_PUBLIC_KEY",
            "AllowedIPs = $PEER_ALLOWED_IPS",
            "PersistentKeepalive = 25",
            "EOF",
            "",
            "# Set proper permissions",
            "chmod 600 /etc/wireguard/wg0.conf",
            "",
            "# Remove any existing WireGuard interface",
            "ip link show wg0 && ip link delete wg0 || true",
            "",
            "# Start WireGuard",
            "systemctl enable wg-quick@wg0",
            "systemctl start wg-quick@wg0",
            "",
            "# Wait for WireGuard interface to be ready",
            "for i in {1..10}; do",
            "  if ip link show wg0 > /dev/null 2>&1; then",
            "    echo 'WireGuard interface wg0 is ready'",
            "    break",
            "  fi",
            "  echo 'Waiting for wg0 interface...'",
            "  sleep 2",
            "done",
            "",
            "# Associate Elastic IP",
            "INSTANCE_ID=$(ec2-metadata --instance-id | cut -d ' ' -f 2)",
            f"EIP_ALLOC_ID={self.elastic_ip.attr_allocation_id}",
            f"aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $EIP_ALLOC_ID --region {self.region} || true",
            "",
            "# Configure CloudWatch Logs",
            "cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<EOF",
            "{",
            '  "logs": {',
            '    "logs_collected": {',
            '      "files": {',
            '        "collect_list": [',
            "          {",
            '            "file_path": "/var/log/messages",',
            '            "log_group_name": "/aws/ec2/wireguard",',
            '            "log_stream_name": "{instance_id}/messages"',
            "          }",
            "        ]",
            "      }",
            "    }",
            "  }",
            "}",
            "EOF",
            "",
            "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \\",
            "  -a fetch-config \\",
            "  -m ec2 \\",
            "  -s \\",
            "  -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json",
            "",
            "# Verify WireGuard is running",
            "echo 'WireGuard setup completed'",
            "systemctl status wg-quick@wg0 || true",
            "wg show || true",
            "ip route show",
        )

        launch_template = ec2.LaunchTemplate(
            self,
            "WireGuardLaunchTemplate",
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
            security_group=wireguard_security_group,
            role=instance_role,
            user_data=user_data,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_size=8,
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        delete_on_termination=True,
                        encrypted=True,
                    ),
                )
            ],
        )
        
        launch_template.node.add_metadata(
            "SourceDestCheck",
            "Disable source/destination check to allow routing"
        )

        Tags.of(launch_template).add("Name", "WireGuardLaunchTemplate")

        self.auto_scaling_group = autoscaling.AutoScalingGroup(
            self,
            "WireGuardASG",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            launch_template=launch_template,
            min_capacity=1,
            max_capacity=1,
            desired_capacity=1,
            health_check=autoscaling.HealthCheck.ec2(
                grace=Duration.minutes(5)
            ),
        )

        Tags.of(self.auto_scaling_group).add("Name", "WireGuardASG")

        self.auto_scaling_group.add_lifecycle_hook(
            "InstanceLaunchingHook",
            lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,
            heartbeat_timeout=Duration.minutes(5),
            default_result=autoscaling.DefaultResult.CONTINUE,
        )

        CfnOutput(
            self,
            "ElasticIP",
            value=self.elastic_ip.ref,
            description="Elastic IP for WireGuard server",
            export_name="WireGuardElasticIP",
        )

        CfnOutput(
            self,
            "AutoScalingGroupName",
            value=self.auto_scaling_group.auto_scaling_group_name,
            description="AutoScaling Group name",
            export_name="WireGuardASGName",
        )
