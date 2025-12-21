import json
import boto3
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')
autoscaling_client = boto3.client('autoscaling')


def handler(event, context):
    """
    Lambda function to update VPC route tables when WireGuard instance launches
    Routes VPN traffic (10.200.0.0/24) to the WireGuard instance
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        vpc_id = os.environ.get('VPC_ID')
        vpn_cidr = os.environ.get('VPN_CIDR', '10.200.0.0/24')
        
        detail = event.get('detail', {})
        instance_id = detail.get('EC2InstanceId')
        lifecycle_hook_name = detail.get('LifecycleHookName')
        auto_scaling_group_name = detail.get('AutoScalingGroupName')
        lifecycle_action_token = detail.get('LifecycleActionToken')
        
        if not instance_id:
            raise ValueError("EC2InstanceId not found in event")
        
        logger.info(f"Processing instance {instance_id}")
        
        # Disable Source/Destination Check
        logger.info(f"Disabling Source/Destination Check for instance {instance_id}")
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            SourceDestCheck={'Value': False}
        )
        logger.info("Source/Destination Check disabled")
        
        # Get instance details
        instance_response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = instance_response['Reservations'][0]['Instances'][0]
        
        # Get primary network interface ID
        network_interface_id = instance['NetworkInterfaces'][0]['NetworkInterfaceId']
        logger.info(f"Network Interface ID: {network_interface_id}")
        
        # Get all route tables in the VPC
        route_tables_response = ec2_client.describe_route_tables(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
            ]
        )
        
        # Update routes in private subnet route tables
        for route_table in route_tables_response['RouteTables']:
            route_table_id = route_table['RouteTableId']
            
            # Check if this is a private subnet route table (no IGW route)
            has_igw = any(
                route.get('GatewayId', '').startswith('igw-')
                for route in route_table['Routes']
            )
            
            if has_igw:
                logger.info(f"Skipping public route table {route_table_id}")
                continue
            
            logger.info(f"Updating route table {route_table_id}")
            
            # Check if route already exists
            route_exists = any(
                route.get('DestinationCidrBlock') == vpn_cidr
                for route in route_table['Routes']
            )
            
            try:
                if route_exists:
                    # Replace existing route
                    ec2_client.replace_route(
                        RouteTableId=route_table_id,
                        DestinationCidrBlock=vpn_cidr,
                        NetworkInterfaceId=network_interface_id
                    )
                    logger.info(f"Replaced route in {route_table_id}")
                else:
                    # Create new route
                    ec2_client.create_route(
                        RouteTableId=route_table_id,
                        DestinationCidrBlock=vpn_cidr,
                        NetworkInterfaceId=network_interface_id
                    )
                    logger.info(f"Created route in {route_table_id}")
            except Exception as route_error:
                logger.error(f"Error updating route in {route_table_id}: {str(route_error)}")
                # Continue with other route tables
        
        # Complete lifecycle action
        if lifecycle_hook_name and auto_scaling_group_name:
            logger.info(f"Completing lifecycle action for {lifecycle_hook_name}")
            autoscaling_client.complete_lifecycle_action(
                LifecycleHookName=lifecycle_hook_name,
                AutoScalingGroupName=auto_scaling_group_name,
                LifecycleActionToken=lifecycle_action_token,
                LifecycleActionResult='CONTINUE',
                InstanceId=instance_id
            )
            logger.info("Lifecycle action completed")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Routes updated successfully',
                'instance_id': instance_id,
                'network_interface_id': network_interface_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error updating routes: {str(e)}", exc_info=True)
        
        if lifecycle_hook_name and auto_scaling_group_name and instance_id:
            try:
                autoscaling_client.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook_name,
                    AutoScalingGroupName=auto_scaling_group_name,
                    LifecycleActionToken=lifecycle_action_token,
                    LifecycleActionResult='ABANDON',
                    InstanceId=instance_id
                )
                logger.info("Lifecycle action abandoned due to error")
            except Exception as abandon_error:
                logger.error(f"Error abandoning lifecycle action: {str(abandon_error)}")
        
        raise
