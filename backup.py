import boto3
import logging
import os
from datetime import datetime, timezone

class BackupManager:
    def __init__(self, access_key, secret_key, region, instance_ids, retention_days):
        self.instance_ids = instance_ids
        self.retention_days = retention_days
        self.ec2 = boto3.client(
            'ec2',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        log_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "ami_backup.log")

        logging.basicConfig(
            filename=log_path,
            level=logging.INFO,
            format='[%(asctime)s] %(message)s',
            datefmt='%Y_%m_%d_%I_%M_%p'
        )
        self.logger = logging.getLogger()

    def log(self, message):
        self.logger.info(message)
        print(message)

    def run(self):
        self.log("🚀 Starting AMI backup and cleanup...")

        for instance_id in self.instance_ids:
            self.log(f"📌 Processing instance: {instance_id}")
            try:
                name_tag = self.ec2.describe_tags(
                    Filters=[
                        {'Name': 'resource-id', 'Values': [instance_id]},
                        {'Name': 'key', 'Values': ['Name']}
                    ]
                )['Tags'][0]['Value']
            except Exception:
                self.log(f"❌ Could not find 'Name' tag for {instance_id}. Skipping...")
                continue

            timestamp = datetime.now().strftime('%Y_%m_%d_%I_%M_%p')
            ami_name = f"{name_tag}_{timestamp}"

            try:
                ami_id = self.ec2.create_image(
                    InstanceId=instance_id,
                    Name=ami_name,
                    NoReboot=True
                )['ImageId']
                self.log(f"✅ AMI creation started: {ami_id} ({ami_name})")

                self.ec2.create_tags(
                    Resources=[ami_id],
                    Tags=[
                        {'Key': 'CreatedBy', 'Value': 'AutoBackup'},
                        {'Key': 'InstanceName', 'Value': name_tag}
                    ]
                )
            except Exception as e:
                self.log(f"❌ Failed to create AMI: {e}")
                continue

            # Cleanup old AMIs
            images = self.ec2.describe_images(
                Owners=['self'],
                Filters=[
                    {'Name': 'tag:CreatedBy', 'Values': ['AutoBackup']},
                    {'Name': 'tag:InstanceName', 'Values': [name_tag]}
                ]
            )['Images']

            now = datetime.now(timezone.utc)
            for image in sorted(images, key=lambda x: x['CreationDate']):
                created_date = datetime.strptime(image['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                age = (now - created_date).days
                if age > self.retention_days:
                    ami_id = image['ImageId']
                    self.log(f"🗑️ Deregistering AMI: {ami_id} (Age: {age} days)")
                    try:
                        snapshot_ids = [
                            mapping['Ebs']['SnapshotId']
                            for mapping in image.get('BlockDeviceMappings', [])
                            if 'Ebs' in mapping
                        ]
                        self.ec2.deregister_image(ImageId=ami_id)
                        for snap in snapshot_ids:
                            self.log(f"   🔸 Deleting snapshot: {snap}")
                            self.ec2.delete_snapshot(SnapshotId=snap)
                    except Exception as e:
                        self.log(f"   ⚠️ Error during deletion: {e}")

            self.log(f"✅ Done with instance: {name_tag} ({instance_id})")
            self.log("--------------------------------------------------")

        self.log("🎉 All tasks completed.")
