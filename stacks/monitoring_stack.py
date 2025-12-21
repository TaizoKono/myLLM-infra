from aws_cdk import (
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_autoscaling as autoscaling,
    Duration,
)
from constructs import Construct


class MonitoringStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        auto_scaling_group: autoscaling.AutoScalingGroup,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        alarm_topic = sns.Topic(
            self,
            "WireGuardAlarmTopic",
            display_name="WireGuard VPN Alarms",
        )

        email = self.node.try_get_context("alarm_email")
        if email:
            alarm_topic.add_subscription(
                subscriptions.EmailSubscription(email)
            )

        instance_down_alarm = cloudwatch.Alarm(
            self,
            "WireGuardInstanceDownAlarm",
            metric=cloudwatch.Metric(
                namespace="AWS/EC2",
                metric_name="StatusCheckFailed",
                dimensions_map={
                    "AutoScalingGroupName": auto_scaling_group.auto_scaling_group_name,
                },
                statistic="Average",
                period=Duration.minutes(1),
            ),
            threshold=1,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            alarm_description="WireGuard instance status check failed",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        instance_down_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))

        cpu_high_alarm = cloudwatch.Alarm(
            self,
            "WireGuardCPUHighAlarm",
            metric=cloudwatch.Metric(
                namespace="AWS/EC2",
                metric_name="CPUUtilization",
                dimensions_map={
                    "AutoScalingGroupName": auto_scaling_group.auto_scaling_group_name,
                },
                statistic="Average",
                period=Duration.minutes(5),
            ),
            threshold=80,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            alarm_description="WireGuard instance CPU utilization is high",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        cpu_high_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))

        network_low_alarm = cloudwatch.Alarm(
            self,
            "WireGuardNetworkLowAlarm",
            metric=cloudwatch.Metric(
                namespace="AWS/EC2",
                metric_name="NetworkIn",
                dimensions_map={
                    "AutoScalingGroupName": auto_scaling_group.auto_scaling_group_name,
                },
                statistic="Sum",
                period=Duration.minutes(10),
            ),
            threshold=1000,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
            alarm_description="WireGuard instance network activity is low (possible connection issue)",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        network_low_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
