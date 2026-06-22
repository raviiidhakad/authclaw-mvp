"""
AuthClaw Backup Validator Lambda

Validates RDS and ElastiCache Redis backups monthly.
Publishes PASS/FAIL result to SNS.
"""

import boto3
import os
import time
import json

REGION        = os.environ.get("AWS_REGION", "us-east-1")
DB_IDENTIFIER = os.environ["DB_IDENTIFIER"]
REDIS_ID      = os.environ["REDIS_GROUP_ID"]
SNS_ARN       = os.environ["SNS_TOPIC_ARN"]
ENVIRONMENT   = os.environ["ENVIRONMENT"]

rds      = boto3.client("rds",           region_name=REGION)
ec       = boto3.client("elasticache",   region_name=REGION)
sns      = boto3.client("sns",           region_name=REGION)


def publish(subject, message):
    sns.publish(TopicArn=SNS_ARN, Subject=subject, Message=message)


def wait_for_rds(identifier, target_status="available", timeout=600):
    elapsed = 0
    while elapsed < timeout:
        resp = rds.describe_db_instances(DBInstanceIdentifier=identifier)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        if status == target_status:
            return True
        time.sleep(15)
        elapsed += 15
    return False


def validate_rds():
    scratch_id = f"authclaw-{ENVIRONMENT}-restore-validate"
    try:
        rds.restore_db_instance_to_point_in_time(
            SourceDBInstanceIdentifier=DB_IDENTIFIER,
            TargetDBInstanceIdentifier=scratch_id,
            UseLatestRestorableTime=True,
            DBInstanceClass="db.t4g.micro",
            MultiAZ=False,
            PubliclyAccessible=False,
        )
        ok = wait_for_rds(scratch_id, "available")
        if ok:
            publish(
                f"[PASS] RDS Backup Validation — {ENVIRONMENT}",
                f"RDS restore of {DB_IDENTIFIER} completed successfully."
            )
        else:
            publish(
                f"[FAIL] RDS Backup Validation — {ENVIRONMENT}",
                f"RDS restore of {DB_IDENTIFIER} did not reach AVAILABLE within timeout."
            )
    except Exception as e:
        publish(
            f"[FAIL] RDS Backup Validation — {ENVIRONMENT}",
            f"RDS restore failed with error: {str(e)}"
        )
    finally:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=scratch_id,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True,
            )
        except Exception:
            pass


def validate_redis():
    scratch_id = f"authclaw-{ENVIRONMENT}-redis-validate"
    try:
        # Describe source to get latest snapshot
        snaps = ec.describe_snapshots(ReplicationGroupId=REDIS_ID)
        if not snaps["Snapshots"]:
            publish(
                f"[FAIL] Redis Backup Validation — {ENVIRONMENT}",
                f"No snapshots found for Redis group {REDIS_ID}"
            )
            return
        snap_name = snaps["Snapshots"][0]["SnapshotName"]
        ec.create_replication_group(
            ReplicationGroupId=scratch_id,
            ReplicationGroupDescription="Backup validation scratch node",
            SnapshotName=snap_name,
            CacheNodeType="cache.t4g.micro",
            AutomaticFailoverEnabled=False,
        )
        # Wait up to 10 minutes
        elapsed = 0
        success = False
        while elapsed < 600:
            resp = ec.describe_replication_groups(ReplicationGroupId=scratch_id)
            status = resp["ReplicationGroups"][0]["Status"]
            if status == "available":
                success = True
                break
            time.sleep(15)
            elapsed += 15

        if success:
            publish(
                f"[PASS] Redis Backup Validation — {ENVIRONMENT}",
                f"Redis restore from snapshot {snap_name} completed successfully."
            )
        else:
            publish(
                f"[FAIL] Redis Backup Validation — {ENVIRONMENT}",
                f"Redis restore from snapshot {snap_name} timed out."
            )
    except Exception as e:
        publish(
            f"[FAIL] Redis Backup Validation — {ENVIRONMENT}",
            f"Redis restore failed with error: {str(e)}"
        )
    finally:
        try:
            ec.delete_replication_group(
                ReplicationGroupId=scratch_id,
                RetainPrimaryCluster=False,
            )
        except Exception:
            pass


def handler(event, context):
    validate_rds()
    validate_redis()
    return {"statusCode": 200, "body": json.dumps("Backup validation complete.")}
