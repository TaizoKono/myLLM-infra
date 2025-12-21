#!/usr/bin/env python3
import aws_cdk as cdk
from stacks.network_stack import NetworkStack
from stacks.wireguard_stack import WireGuardStack
from stacks.automation_stack import AutomationStack
from stacks.monitoring_stack import MonitoringStack

app = cdk.App()

env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region") or "ap-northeast-1"
)

network_stack = NetworkStack(
    app,
    "WireGuardNetworkStack",
    env=env,
    description="Network infrastructure for WireGuard VPN connection"
)

wireguard_stack = WireGuardStack(
    app,
    "WireGuardStack",
    vpc=network_stack.vpc,
    wireguard_security_group=network_stack.wireguard_security_group,
    env=env,
    description="WireGuard EC2 instance with AutoScaling Group"
)

automation_stack = AutomationStack(
    app,
    "WireGuardAutomationStack",
    vpc=network_stack.vpc,
    auto_scaling_group=wireguard_stack.auto_scaling_group,
    elastic_ip=wireguard_stack.elastic_ip,
    env=env,
    description="Lambda functions for WireGuard automation"
)

monitoring_stack = MonitoringStack(
    app,
    "WireGuardMonitoringStack",
    auto_scaling_group=wireguard_stack.auto_scaling_group,
    env=env,
    description="CloudWatch monitoring and alarms for WireGuard"
)

app.synth()
