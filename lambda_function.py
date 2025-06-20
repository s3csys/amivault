import json
import boto3
import os
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    AWS Lambda function to create AMI backups for EC2 instances
    
    Expected event format:
    {
        "instance_id": "i-1234567890abcdef0",
        "action": "backup",
        "endpoint": "https://your-api-endpoint/api/backup-callback" (optional)
    }
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract parameters from the event
        instance_id = event.get('instance_id')
        action = event.get('action', 'backup')
        endpoint = event.get('endpoint')
        
        if not instance_id:
            logger.error("No instance_id provided in the event")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No instance_id provided'})
            }
        
        # Get the instance region
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response.get('Reservations') or not response['Reservations'][0].get('Instances'):
            logger.error(f"Instance {instance_id} not found")
            return {
                'statusCode': 404,
                'body': json.dumps({'error': f"Instance {instance_id} not found"})
            }
        
        instance = response['Reservations'][0]['Instances'][0]
        region = instance['Placement']['AvailabilityZone'][:-1]  # Remove the AZ letter to get the region
        
        # Get instance name from tags
        instance_name = instance_id
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                instance_name = tag['Value']
                break
        
        # Create AMI
        timestamp = datetime.now().strftime("%Y_%m_%d_%I_%M_%p")
        ami_name = f"{instance_name}_{timestamp}_eventbridge"
        
        ec2_client = boto3.client('ec2', region_name=region)
        ami_response = ec2_client.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            Description=f"Automated backup created by AMIVault Lambda function at {timestamp}",
            NoReboot=True
        )
        
        ami_id = ami_response['ImageId']
        logger.info(f"Created AMI {ami_id} for instance {instance_id}")
        
        # Tag the AMI
        ec2_client.create_tags(
            Resources=[ami_id],
            Tags=[
                {'Key': 'CreatedBy', 'Value': 'AMIVault-Lambda'},
                {'Key': 'InstanceId', 'Value': instance_id},
                {'Key': 'InstanceName', 'Value': instance_name},
                {'Key': 'BackupType', 'Value': 'eventbridge'}
            ]
        )
        
        # Call back to the API endpoint if provided
        if endpoint:
            try:
                import urllib3
                http = urllib3.PoolManager()
                
                callback_data = {
                    'instance_id': instance_id,
                    'ami_id': ami_id,
                    'ami_name': ami_name,
                    'status': 'success',
                    'timestamp': timestamp
                }
                
                response = http.request(
                    'POST',
                    endpoint,
                    body=json.dumps(callback_data).encode('utf-8'),
                    headers={'Content-Type': 'application/json'}
                )
                
                logger.info(f"Callback to {endpoint} returned status {response.status}")
            except Exception as e:
                logger.error(f"Error calling back to endpoint {endpoint}: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'ami_id': ami_id,
                'ami_name': ami_name,
                'instance_id': instance_id,
                'instance_name': instance_name
            })
        }
        
    except Exception as e:
        logger.error(f"Error creating AMI backup: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }