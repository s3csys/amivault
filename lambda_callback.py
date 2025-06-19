from flask import Blueprint, request, jsonify
from models import db, Backup, Instance
from datetime import datetime, UTC
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create a Blueprint for the Lambda callback routes
lambda_callback = Blueprint('lambda_callback', __name__)

@lambda_callback.route('/api/backup-callback', methods=['POST'])
def backup_callback():
    """
    Endpoint to receive callbacks from the Lambda function after AMI creation
    
    Expected JSON payload:
    {
        "instance_id": "i-1234567890abcdef0",
        "ami_id": "ami-1234567890abcdef0",
        "ami_name": "AMIVault-instance-name-20230101-123456",
        "status": "success",
        "timestamp": "20230101-123456"
    }
    """
    try:
        # Get the JSON data from the request
        data = request.get_json()
        
        if not data:
            logger.error("No JSON data received in callback")
            return jsonify({'error': 'No data received'}), 400
        
        # Extract data from the payload
        instance_id = data.get('instance_id')
        ami_id = data.get('ami_id')
        ami_name = data.get('ami_name')
        status = data.get('status', 'unknown')
        timestamp_str = data.get('timestamp')
        
        # Validate required fields
        if not all([instance_id, ami_id, ami_name]):
            logger.error(f"Missing required fields in callback data: {data}")
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Get the instance from the database
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            logger.warning(f"Instance {instance_id} not found in database for callback")
            return jsonify({'error': 'Instance not found'}), 404
        
        # Parse timestamp or use current time
        try:
            if timestamp_str:
                timestamp = datetime.strptime(timestamp_str, "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
            else:
                timestamp = datetime.now(UTC)
        except ValueError:
            logger.warning(f"Invalid timestamp format: {timestamp_str}, using current time")
            timestamp = datetime.now(UTC)
        
        # Create or update backup record
        existing_backup = Backup.query.filter_by(instance_id=instance_id, ami_id=ami_id).first()
        
        if existing_backup:
            # Update existing backup
            existing_backup.status = 'Success' if status == 'success' else 'Failed'
            existing_backup.ami_name = ami_name
            existing_backup.timestamp = timestamp
            db.session.commit()
            logger.info(f"Updated existing backup record for AMI {ami_id}")
        else:
            # Create new backup record
            backup = Backup(
                instance_id=instance_id,
                ami_id=ami_id,
                ami_name=ami_name,
                status='Success' if status == 'success' else 'Failed',
                timestamp=timestamp,
                retention_days=instance.retention_days
            )
            db.session.add(backup)
            db.session.commit()
            logger.info(f"Created new backup record for AMI {ami_id}")
        
        return jsonify({
            'success': True,
            'message': f"Backup record {'updated' if existing_backup else 'created'} for AMI {ami_id}"
        })
        
    except Exception as e:
        logger.error(f"Error processing Lambda callback: {str(e)}")
        return jsonify({'error': str(e)}), 500