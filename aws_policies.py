import boto3
import json


def get_policy(policy_arn, profile):
    if profile:
        boto3.setup_default_session(profile_name=profile)
    iam_resource = boto3.resource('iam')

    policy = iam_resource.Policy(policy_arn)
    policy_version = iam_resource.PolicyVersion(policy.arn, policy.default_version_id)
    print(json.dumps(policy_version.document, indent=4))
    return

