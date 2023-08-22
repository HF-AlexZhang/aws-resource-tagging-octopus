import yaml
from config import RESOURCE_FILE, tags
from tag_resources import (
    IAM,
    RDS,
    S3,
    SecretsManager,
    ELB,
    Alarm,
    ElastiCache,
    Lambda,
    SES,
    OpenSearch,
)


class TestResourceTagging:
    def setup_method(self):
        with open(RESOURCE_FILE) as file:
            self.aws_resources = yaml.safe_load(file)
        self.iam = IAM()
        self.rds = RDS()
        self.s3 = S3()
        self.secrets_manager = SecretsManager()
        self.elb = ELB()
        self.alarm = Alarm()
        self.elasticache = ElastiCache()
        self.aws_lambda = Lambda()
        self.ses = SES()
        self.opensearch = OpenSearch()

    def test_iam_resources_have_proper_tags(self):
        print("\n---- Testing IAM ----")
        for policy in self.aws_resources.get("iam_policies", []):
            current_tags = self.iam.get_policy_tags(policy)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for IAM policy {policy}"
            print(f"IAM policy {policy} has proper tags ✅")

        for role in self.aws_resources.get("iam_roles", []):
            current_tags = self.iam.get_role_tags(role)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for IAM role {role}"
            print(f"IAM role {role} has proper tags ✅")

    def test_rds_resources_have_proper_tags(self):
        print("\n---- Testing RDS ----")
        for arn in self.aws_resources.get("rds_arns", []):
            current_tags = self.rds.get_tags(arn)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for RDS resource {arn}"
            print(f"RDS resource {arn} has proper tags ✅")

    def test_s3_resources_have_proper_tags(self):
        print("\n---- Testing S3 ----")
        for bucket in self.aws_resources.get("s3_buckets", []):
            current_tags = self.s3.get_bucket_tags(bucket)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for S3 bucket {bucket}"
            print(f"S3 bucket {bucket} has proper tags ✅")

    def test_secrets_manager_resources_have_proper_tags(self):
        print("\n---- Testing Secrets Manager ----")
        for secret_suffix in self.aws_resources.get("secrets", []):
            current_tags = self.secrets_manager.get_tags(secret_suffix)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for Secrets Manager secret {secret_suffix}"
            print(f"Secrets Manager secret {secret_suffix} has proper tags ✅")

    def test_elb_resources_have_proper_tags(self):
        print("\n---- Testing ELB ----")
        for arn in self.aws_resources.get("elb_arns", []):
            current_tags = self.elb.get_tags(arn)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for ELB resource {arn}"
            print(f"ELB resource {arn} has proper tags ✅")

    def test_alarm_resources_have_proper_tags(self):
        print("\n---- Testing CloudWatch Alarms ----")
        for arn in self.aws_resources.get("alarm_arns", []):
            current_tags = self.alarm.get_tags(arn)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for CloudWatch Alarm {arn}"
            print(f"CloudWatch Alarm {arn} has proper tags ✅")

    def test_elasticache_resources_have_proper_tags(self):
        print("\n---- Testing ElastiCache ----")
        for arn in self.aws_resources.get("elasticache_arns", []):
            current_tags = self.elasticache.get_tags(arn)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for ElastiCache resource {arn}"
            print(f"ElastiCache resource {arn} has proper tags ✅")

    def test_lambda_resources_have_proper_tags(self):
        print("\n---- Testing Lambda ----")
        for arn in self.aws_resources.get("lambda_arns", []):
            current_tags = self.aws_lambda.get_tags(arn)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for Lambda function {arn}"
            print(f"Lambda function {arn} has proper tags ✅")

    def test_ses_resources_have_proper_tags(self):
        print("\n---- Testing SES ----")
        for arn in self.aws_resources.get("ses_arns", []):
            current_tags = self.ses.get_tags(arn)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for SES resource {arn}"
            print(f"SES resource {arn} has proper tags ✅")

    def test_opensearch_resources_have_proper_tags(self):
        print("\n---- Testing OpenSearch ----")
        for arn in self.aws_resources.get("opensearch_arns", []):
            current_tags = self.opensearch.get_tags(arn)
            assert all(
                tag in current_tags.items() for tag in tags.items()
            ), f"Missing expected tags for OpenSearch resource {arn}"
            print(f"OpenSearch resource {arn} has proper tags ✅")
