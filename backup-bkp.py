#!/usr/bin/env python3

import boto3
import logging
import time
from datetime import datetime, timezone
import os


def setup_logging():
    os.makedirs("logs", exist_ok=True)
    log_file = os.path.join("logs", "ami_backup.log")
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='[%(asctime)s] %(message)s',
        datefmt='%Y_%m_%d_%I_%M_%p'
    )
    return logging.getLogger()


def get_instance_name(ec2, instance_id):
    try:
        tags = ec2.describe_tags(
            Filters=[
                {'Name': 'resource-id', 'Values': [instance_id]},
                {'Name': 'key', 'Values': ['Name']}
            ]
        ).get("Tags", [])
        for tag in tags:
            if tag['Key'] == 'Name':
                return tag['Value']
    except Exception as e:
        log.error(f"⚠️ Error getting tags for {instance_id}: {str(e)}")
    return None


def create_ami(ec2, instance_id, ami_name):
    try:
        response = ec2.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            NoReboot=True
        )
        return response['ImageId']
    except Exception as e:
        log.error(f"❌ Failed to create AMI for {instance_id}: {str(e)}")
        return None


def tag_ami(ec2, ami_id, instance_name):
    ec2.create_tags(
        Resources=[ami_id],
        Tags=[
            {'Key': 'CreatedBy', 'Value': 'AutoBackup'},
            {'Key': 'InstanceName', 'Value': instance_name}
        ]
    )


def cleanup_old_amis(ec2, instance_name, retention_days):
    log.info("🔍 Checking for old AMIs...")
    try:
        images = ec2.describe_images(
            Owners=['self'],
            Filters=[
                {'Name': 'tag:CreatedBy', 'Values': ['AutoBackup']},
                {'Name': 'tag:InstanceName', 'Values': [instance_name]}
            ]
        )['Images']
    except Exception as e:
        log.error(f"⚠️ Failed to fetch AMIs: {str(e)}")
        return

    now = datetime.now(timezone.utc)
    for image in sorted(images, key=lambda x: x['CreationDate']):
        creation_date = datetime.strptime(image['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        age = (now - creation_date).days

        if age > retention_days:
            ami_id = image['ImageId']
            log.info(f"🗑️ Deregistering AMI {ami_id} (Age: {age} days)")

            ec2.deregister_image(ImageId=ami_id)

            for mapping in image.get('BlockDeviceMappings', []):
                if 'Ebs' in mapping:
                    snapshot_id = mapping['Ebs']['SnapshotId']
                    try:
                        ec2.delete_snapshot(SnapshotId=snapshot_id)
                        log.info(f"   🔸 Deleted snapshot: {snapshot_id}")
                    except Exception as e:
                        log.error(f"   ⚠️ Error deleting snapshot {snapshot_id}: {str(e)}")


def run_backup(config):
    global log
    log = setup_logging()

    log.info("🚀 Starting AMI backup and cleanup...")

    boto3.setup_default_session(
        aws_access_key_id=config["aws_access_key_id"],
        aws_secret_access_key=config["aws_secret_access_key"],
        region_name=config.get("region", "ap-south-1")
    )
    ec2 = boto3.client("ec2")

    for instance_id in config["instance_ids"]:
        log.info(f"📌 Processing instance: {instance_id}")
        instance_name = get_instance_name(ec2, instance_id)

        if not instance_name:
            log.error(f"❌ Could not find 'Name' tag for {instance_id}. Skipping...")
            continue

        timestamp = datetime.now().strftime("%Y_%m_%d_%I_%M_%p")
        ami_name = f"{instance_name}_{timestamp}"

        ami_id = create_ami(ec2, instance_id, ami_name)
        if not ami_id:
            continue

        log.info(f"✅ AMI creation started: {ami_id} ({ami_name})")
        time.sleep(5)
        tag_ami(ec2, ami_id, instance_name)

        cleanup_old_amis(ec2, instance_name, config.get("retention_days", 7))

        log.info(f"✅ Done with instance: {instance_name} ({instance_id})")
        log.info("--------------------------------------------------")

    log.info("🎉 All tasks completed.")
