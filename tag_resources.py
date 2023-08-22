import boto3
from typing import Dict
import yaml
from config import ACCOUNT_ID, RESOURCE_FILE, aws_tags, tags


class IAM:
    def __init__(self):
        self.iam_client = boto3.client("iam")

    def get_policy_tags(self, policy_name: str) -> Dict[str, str]:
        policy_arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/{policy_name}"
        response = self.iam_client.list_policy_tags(PolicyArn=policy_arn)
        return {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    def get_role_tags(self, role_name: str) -> Dict[str, str]:
        response = self.iam_client.list_role_tags(RoleName=role_name)
        return {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    def add_policy_tags(self, policy_name: str) -> None:
        policy_arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/{policy_name}"
        self.iam_client.tag_policy(PolicyArn=policy_arn, Tags=aws_tags)

    def add_role_tags(self, role_name: str) -> None:
        self.iam_client.tag_role(RoleName=role_name, Tags=aws_tags)


class RDS:
    def __init__(self):
        self.client = boto3.client("rds")

    def get_tags(self, resource_arn: str) -> Dict[str, str]:
        response = self.client.list_tags_for_resource(ResourceName=resource_arn)
        return {tag["Key"]: tag["Value"] for tag in response["TagList"]}

    def add_tags(self, resource_arn: str) -> None:
        self.client.add_tags_to_resource(ResourceName=resource_arn, Tags=aws_tags)


class S3:
    def __init__(self):
        self.client = boto3.client("s3")

    def get_bucket_tags(self, bucket_name: str) -> Dict[str, str]:
        response = self.client.get_bucket_tagging(Bucket=bucket_name)
        return {tag["Key"]: tag["Value"] for tag in response["TagSet"]}

    def add_bucket_tags(self, bucket_name: str) -> None:
        self.client.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": aws_tags})


class SecretsManager:
    def __init__(self):
        self.client = boto3.client("secretsmanager")

    def get_tags(self, secret_suffix: str) -> Dict[str, str]:
        arn = (
            f"arn:aws:secretsmanager:ap-southeast-2:{ACCOUNT_ID}:secret:{secret_suffix}"
        )
        response = self.client.describe_secret(SecretId=arn)
        return {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    def add_tags(self, secret_suffix: str) -> None:
        arn = (
            f"arn:aws:secretsmanager:ap-southeast-2:{ACCOUNT_ID}:secret:{secret_suffix}"
        )
        self.client.tag_resource(SecretId=arn, Tags=aws_tags)


class ELB:
    def __init__(self):
        self.client = boto3.client("elbv2")

    def get_tags(self, resource_arn: str) -> Dict[str, str]:
        response = self.client.describe_tags(ResourceArns=[resource_arn])
        return {
            tag["Key"]: tag["Value"] for tag in response["TagDescriptions"][0]["Tags"]
        }

    def add_tags(self, resource_arn: str) -> None:
        self.client.add_tags(ResourceArns=[resource_arn], Tags=aws_tags)


class Alarm:
    def __init__(self):
        self.client = boto3.client("cloudwatch")

    def get_tags(self, resource_arn: str) -> Dict[str, str]:
        response = self.client.list_tags_for_resource(ResourceARN=resource_arn)
        return {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    def add_tags(self, resource_arn: str) -> None:
        self.client.tag_resource(ResourceARN=resource_arn, Tags=aws_tags)


class ElastiCache:
    def __init__(self):
        self.client = boto3.client("elasticache")

    def get_tags(self, resource_arn: str) -> Dict[str, str]:
        response = self.client.list_tags_for_resource(ResourceName=resource_arn)
        return {tag["Key"]: tag["Value"] for tag in response["TagList"]}

    def add_tags(self, resource_arn: str) -> None:
        self.client.add_tags_to_resource(ResourceName=resource_arn, Tags=aws_tags)


class Lambda:
    def __init__(self):
        self.client = boto3.client("lambda")

    def get_tags(self, resource_arn: str) -> Dict[str, str]:
        response = self.client.list_tags(Resource=resource_arn)
        return {key: response["Tags"][key] for key in response["Tags"]}

    def add_tags(self, resource_arn: str) -> None:
        self.client.tag_resource(Resource=resource_arn, Tags=tags)


class SES:
    def __init__(self):
        self.client = boto3.client("sesv2")

    def get_tags(self, resource_arn: str) -> Dict[str, str]:
        response = self.client.list_tags_for_resource(ResourceArn=resource_arn)
        return {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    def add_tags(self, resource_arn: str) -> None:
        self.client.tag_resource(ResourceArn=resource_arn, Tags=aws_tags)


class OpenSearch:
    def __init__(self):
        self.client = boto3.client("opensearch")

    def get_tags(self, resource_arn: str) -> Dict[str, str]:
        response = self.client.list_tags(ARN=resource_arn)
        return {tag["Key"]: tag["Value"] for tag in response["TagList"]}

    def add_tags(self, resource_arn: str) -> None:
        self.client.add_tags(ARN=resource_arn, TagList=aws_tags)


class ResourceTagger:
    def __init__(self, resources):
        self.resources = resources

    def process_iam(self) -> None:
        iam = IAM()
        for policy in self.resources.get("iam_policies", []):
            iam.add_policy_tags(policy)
        for role in self.resources.get("iam_roles", []):
            iam.add_role_tags(role)

    def process_rds(self) -> None:
        rds = RDS()
        for arn in self.resources.get("rds_arns", []):
            rds.add_tags(arn)

    def process_s3(self) -> None:
        s3 = S3()
        for bucket in self.resources.get("s3_buckets", []):
            s3.add_bucket_tags(bucket)

    def process_secrets_manager(self) -> None:
        secrets_manager = SecretsManager()
        for secret_suffix in self.resources.get("secrets", []):
            secrets_manager.add_tags(secret_suffix)

    def process_elb(self) -> None:
        elb = ELB()
        for arn in self.resources.get("elb_arns", []):
            elb.add_tags(arn)

    def process_alarms(self) -> None:
        alarm = Alarm()
        for arn in self.resources.get("alarm_arns", []):
            alarm.add_tags(arn)

    def process_elasticache(self) -> None:
        elasticache = ElastiCache()
        for arn in self.resources.get("elasticache_arns", []):
            elasticache.add_tags(arn)

    def process_lambda(self) -> None:
        aws_lambda = Lambda()
        for arn in self.resources.get("lambda_arns", []):
            aws_lambda.add_tags(arn)

    def process_ses(self) -> None:
        ses = SES()
        for arn in self.resources.get("ses_arns", []):
            ses.add_tags(arn)

    def process_opensearch(self) -> None:
        opensearch = OpenSearch()
        for arn in self.resources.get("opensearch_arns", []):
            opensearch.add_tags(arn)


def main():
    with open(RESOURCE_FILE) as file:
        aws_resources = yaml.safe_load(file)

    tagger = ResourceTagger(aws_resources)

    tagger.process_iam()
    tagger.process_rds()
    tagger.process_s3()
    tagger.process_secrets_manager()
    tagger.process_elb()
    tagger.process_alarms()
    tagger.process_elasticache()
    tagger.process_lambda()
    tagger.process_ses()
    tagger.process_opensearch()


if __name__ == "__main__":
    main()
