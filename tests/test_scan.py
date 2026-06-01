import boto3
from moto import mock_aws

from main import scan


def setup_aws(session):
    account = session.client("sts").get_caller_identity()["Account"]
    s3 = session.client("s3")
    s3.create_bucket(Bucket="logs-bucket")
    s3.create_bucket(Bucket="app-data")
    s3.put_bucket_versioning(Bucket="app-data", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(
        Bucket="app-data",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    ct = session.client("cloudtrail")
    ct.create_trail(
        Name="trail",
        S3BucketName="logs-bucket",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
    )
    ct.start_logging(Name="trail")

    session.client("ec2").create_security_group(GroupName="web", Description="web")

    cfg = session.client("config")
    cfg.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": f"arn:aws:iam::{account}:role/config",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        }
    )
    cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "logs-bucket"})
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")


@mock_aws
def test_scan_runs():
    setup_aws(boto3.Session(region_name="us-east-1"))
    report = scan(region="us-east-1")
    assert report["summary"]["account"]
    assert report["summary"]["score"] >= 0
    assert len(report["items"]) > 5
