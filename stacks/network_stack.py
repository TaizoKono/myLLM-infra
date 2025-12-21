from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_iam as iam,
    CfnOutput,
    Tags,
)
from constructs import Construct


class NetworkStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.vpc = ec2.Vpc(
            self,
            "WireGuardVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True,
        )

        Tags.of(self.vpc).add("Name", "WireGuardVPC")

        # VPC Flow Logs
        flow_log_group = logs.LogGroup(
            self,
            "VPCFlowLogGroup",
            log_group_name="/aws/vpc/wireguard-flowlogs",
            retention=logs.RetentionDays.ONE_MONTH,
        )

        flow_log_role = iam.Role(
            self,
            "VPCFlowLogRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
        )

        flow_log_group.grant_write(flow_log_role)

        self.vpc.add_flow_log(
            "VPCFlowLog",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                log_group=flow_log_group,
                iam_role=flow_log_role,
            ),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )

        self.wireguard_security_group = ec2.SecurityGroup(
            self,
            "WireGuardSecurityGroup",
            vpc=self.vpc,
            description="Security group for WireGuard VPN server",
            allow_all_outbound=False,
        )

        local_ip = self.node.try_get_context("local_llm_ip")
        if local_ip:
            self.wireguard_security_group.add_ingress_rule(
                peer=ec2.Peer.ipv4(f"{local_ip}/32"),
                connection=ec2.Port.udp(51820),
                description="WireGuard VPN from local LLM server",
            )
        else:
            self.wireguard_security_group.add_ingress_rule(
                peer=ec2.Peer.any_ipv4(),
                connection=ec2.Port.udp(51820),
                description="WireGuard VPN (configure local_llm_ip in cdk.context.json)",
            )

        self.wireguard_security_group.add_ingress_rule(
            peer=ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from VPC",
        )

        self.wireguard_security_group.add_ingress_rule(
            peer=ec2.Peer.ipv4("10.200.0.0/24"),
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from WireGuard VPN network",
        )

        local_llm_server_vpn_ip = self.node.try_get_context("local_llm_server_vpn_ip")
        if local_llm_server_vpn_ip:
            self.wireguard_security_group.add_ingress_rule(
                peer=ec2.Peer.ipv4(f"{local_llm_server_vpn_ip}/32"),
                connection=ec2.Port.all_traffic(),
                description="Allow all traffic from local LLM server via VPN",
            )

        # Outbound rules - restricted to necessary traffic only
        # 1. VPN traffic
        self.wireguard_security_group.add_egress_rule(
            peer=ec2.Peer.ipv4("10.200.0.0/24"),
            connection=ec2.Port.all_traffic(),
            description="Allow VPN traffic",
        )

        # 2. VPC internal traffic
        self.wireguard_security_group.add_egress_rule(
            peer=ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            connection=ec2.Port.all_traffic(),
            description="Allow VPC internal traffic",
        )

        # 3. HTTPS for AWS services and package updates
        self.wireguard_security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS for AWS services and updates",
        )

        # 4. HTTP for package updates
        self.wireguard_security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(80),
            description="Allow HTTP for package updates",
        )

        # 5. DNS resolution
        self.wireguard_security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.udp(53),
            description="Allow DNS resolution",
        )

        # 6. NTP for time synchronization
        self.wireguard_security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.udp(123),
            description="Allow NTP for time synchronization",
        )

        Tags.of(self.wireguard_security_group).add("Name", "WireGuardSecurityGroup")

        # Network ACLs for additional security layer
        # Public subnet NACL
        public_nacl = ec2.NetworkAcl(
            self,
            "PublicNACL",
            vpc=self.vpc,
            subnet_selection=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC
            ),
        )

        # Inbound: WireGuard UDP 51820 from specific IP
        local_ip = self.node.try_get_context("local_llm_ip")
        if local_ip:
            public_nacl.add_entry(
                "AllowWireGuardInbound",
                cidr=ec2.AclCidr.ipv4(f"{local_ip}/32"),
                rule_number=100,
                traffic=ec2.AclTraffic.udp_port(51820),
                direction=ec2.TrafficDirection.INGRESS,
                rule_action=ec2.Action.ALLOW,
            )

        # Inbound: Ephemeral ports for return traffic
        public_nacl.add_entry(
            "AllowEphemeralInbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=110,
            traffic=ec2.AclTraffic.tcp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        # Inbound: UDP ephemeral ports
        public_nacl.add_entry(
            "AllowUDPEphemeralInbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=120,
            traffic=ec2.AclTraffic.udp_port_range(1024, 65535),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        # Outbound: All traffic (controlled by Security Groups)
        public_nacl.add_entry(
            "AllowAllOutbound",
            cidr=ec2.AclCidr.any_ipv4(),
            rule_number=100,
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        Tags.of(public_nacl).add("Name", "WireGuardPublicNACL")

        # Private subnet NACL
        private_nacl = ec2.NetworkAcl(
            self,
            "PrivateNACL",
            vpc=self.vpc,
            subnet_selection=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
        )

        # Inbound: VPC internal traffic only
        private_nacl.add_entry(
            "AllowVPCInbound",
            cidr=ec2.AclCidr.ipv4(self.vpc.vpc_cidr_block),
            rule_number=100,
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        # Inbound: VPN network traffic
        private_nacl.add_entry(
            "AllowVPNInbound",
            cidr=ec2.AclCidr.ipv4("10.200.0.0/24"),
            rule_number=110,
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        # Outbound: VPC internal traffic only
        private_nacl.add_entry(
            "AllowVPCOutbound",
            cidr=ec2.AclCidr.ipv4(self.vpc.vpc_cidr_block),
            rule_number=100,
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        # Outbound: VPN network traffic
        private_nacl.add_entry(
            "AllowVPNOutbound",
            cidr=ec2.AclCidr.ipv4("10.200.0.0/24"),
            rule_number=110,
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        Tags.of(private_nacl).add("Name", "WireGuardPrivateNACL")

        CfnOutput(
            self,
            "VpcId",
            value=self.vpc.vpc_id,
            description="VPC ID",
            export_name="WireGuardVpcId",
        )

        CfnOutput(
            self,
            "SecurityGroupId",
            value=self.wireguard_security_group.security_group_id,
            description="WireGuard Security Group ID",
            export_name="WireGuardSecurityGroupId",
        )
