import json
import boto3
import time
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ssm_client = boto3.client('ssm')
ec2_client = boto3.client('ec2')


def handler(event, context):
    """
    Lambda function to restore WireGuard configuration on newly launched instance
    This is a backup mechanism in case User Data fails
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        detail = event.get('detail', {})
        instance_id = detail.get('EC2InstanceId')
        
        if not instance_id:
            raise ValueError("EC2InstanceId not found in event")
        
        logger.info(f"Checking WireGuard configuration for instance {instance_id}")
        
        max_retries = 5
        retry_delay = 30
        
        for attempt in range(max_retries):
            try:
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                instance_state = response['Reservations'][0]['Instances'][0]['State']['Name']
                
                if instance_state != 'running':
                    logger.info(f"Instance {instance_id} is in state {instance_state}, waiting...")
                    time.sleep(retry_delay)
                    continue
                
                logger.info(f"Instance {instance_id} is running, checking SSM connectivity")
                
                ssm_response = ssm_client.describe_instance_information(
                    Filters=[
                        {
                            'Key': 'InstanceIds',
                            'Values': [instance_id]
                        }
                    ]
                )
                
                if not ssm_response.get('InstanceInformationList'):
                    logger.info(f"Instance {instance_id} not yet registered with SSM, waiting...")
                    time.sleep(retry_delay)
                    continue
                
                logger.info(f"Instance {instance_id} is SSM-ready, verifying WireGuard status")
                
                command_response = ssm_client.send_command(
                    InstanceIds=[instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={
                        'commands': [
                            'systemctl is-active wg-quick@wg0 || exit 1',
                            'wg show wg0 || exit 1'
                        ]
                    },
                    TimeoutSeconds=60
                )
                
                command_id = command_response['Command']['CommandId']
                
                time.sleep(10)
                
                invocation_response = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                
                if invocation_response['Status'] == 'Success':
                    logger.info(f"WireGuard is running correctly on instance {instance_id}")
                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'message': 'WireGuard is running',
                            'instance_id': instance_id
                        })
                    }
                else:
                    logger.warning(f"WireGuard check failed, status: {invocation_response['Status']}")
                    logger.warning(f"Output: {invocation_response.get('StandardOutputContent', '')}")
                    logger.warning(f"Error: {invocation_response.get('StandardErrorContent', '')}")
                
            except Exception as retry_error:
                logger.warning(f"Attempt {attempt + 1}/{max_retries} failed: {str(retry_error)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise
        
        logger.error(f"Failed to verify WireGuard status after {max_retries} attempts")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to verify WireGuard status',
                'instance_id': instance_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error in WireGuard restore: {str(e)}", exc_info=True)
        raise
