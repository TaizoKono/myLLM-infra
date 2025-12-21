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
    Lambda function to attach Elastic IP to newly launched EC2 instance
    Triggered by AutoScaling Group lifecycle hook
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        eip_allocation_id = os.environ.get('EIP_ALLOCATION_ID')
        if not eip_allocation_id:
            raise ValueError("EIP_ALLOCATION_ID environment variable not set")
        
        detail = event.get('detail', {})
        instance_id = detail.get('EC2InstanceId')
        lifecycle_hook_name = detail.get('LifecycleHookName')
        auto_scaling_group_name = detail.get('AutoScalingGroupName')
        lifecycle_action_token = detail.get('LifecycleActionToken')
        
        if not instance_id:
            raise ValueError("EC2InstanceId not found in event")
        
        logger.info(f"Attaching EIP {eip_allocation_id} to instance {instance_id}")
        
        response = ec2_client.associate_address(
            AllocationId=eip_allocation_id,
            InstanceId=instance_id,
            AllowReassociation=True
        )
        
        logger.info(f"EIP attached successfully: {response}")
        
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
                'message': 'EIP attached successfully',
                'instance_id': instance_id,
                'eip_allocation_id': eip_allocation_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error attaching EIP: {str(e)}", exc_info=True)
        
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
