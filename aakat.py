import boto3
import argparse
import re
import json
import time


def validate_access_key_id(key_id):
    # RegEx pattern for AWS Access Key ID
    # taken from https://aws.amazon.com/blogs/security/a-safer-way-to-distribute-aws-credentials-to-ec2/
    key_id_pattern = re.compile('(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])')
    if not key_id_pattern.match(key_id):
        msg = "Supplied Access Key ID doesn't match AWS Access Key ID Format"
        raise argparse.ArgumentTypeError(msg)
    else:
        return (key_id)


# Parse group names out of dict returned by iam_client.list_groups_for_user(UserName='user')
def parse_groups(aws_group_dict):
    group_info = []
    if aws_group_dict:
        for g in aws_group_dict['Groups']:
            group_info.append(g['GroupName'])
    return group_info


# Parse inline policy names out of dict returned by iam_client.list_user_policies(UserName='user')
def parse_inline_polices(aws_inline_polices):
    inline_polices = []
    if aws_inline_polices:
        # print(aws_inline_polices)
        for p in aws_inline_polices['PolicyNames']:
            inline_polices.append(p)
            # print(p)
    return inline_polices


# Parse attached policy names out of dict returned by iam_client.list_attached_user_policies(UserName='user')
def parse_attached_polices(aws_attached_polices):
    attached_polices = []
    if aws_attached_polices:
        # print(aws_attached_polices)
        for p in aws_attached_polices['AttachedPolicies']:
            # print("{0} \t {1}".format(p['PolicyName'], p['PolicyArn']))
            attached_polices.append([p['PolicyName'], p['PolicyArn']])
    return attached_polices


# Get parameters
parser = argparse.ArgumentParser(description='''
                                  Search AWS account for Access Key ID and return user and 
                                  permission details if found.\n
                                  Uses default aws credentials as per AWS CLI''')
parser.add_argument('aws_access_key_id',
                    type=validate_access_key_id,
                    help='Specify AWS Access Key ID')
parser.add_argument('--aws-profile',
                    help='Specify amazon profile to use.',
                    default=None,
                    dest='profile')

args = parser.parse_args()


# Create AWS client/ resource
if args.profile:
    boto3.setup_default_session(profile_name=args.profile)
iam_client = boto3.client('iam')
iam_resource = boto3.resource('iam')
ec2_client = boto3.client('ec2')
#cloudtrail_client = boto3.client('cloudtrail')

# get a list of AWS regions, exclude disabled regions
regions = []
response = ec2_client.describe_regions(AllRegions=False)
for i in response['Regions']:
    regions.append(i['RegionName'])


# search users for access key ID
aws_user = None
for user in iam_resource.users.all():
    for key in user.access_keys.all():
        if args.aws_access_key_id == key.id:
            print(f"Access Key ID {key.id} belongs user to user {key.user_name}")
            aws_user = key.user_name

if not aws_user:
    #  search CloudTrail for access key activity: CloudTrail only searches previous 90 days
    for region in regions:
        print(f"Checking Region {region} for events.")
        cloudtrail_client = boto3.client('cloudtrail', region_name=region)
        response = cloudtrail_client.lookup_events(LookupAttributes=[{'AttributeKey': 'AccessKeyId', 'AttributeValue':args.aws_access_key_id}, ], MaxResults=1)
        if (len(response['Events'])) > 0:
            data = json.loads(response['Events'][0]['CloudTrailEvent'])
            print(
                f"CloudTrail record found in region {region}: "
                f"Access Key ID: {args.aws_access_key_id} "
                f"is associated with user: {data['userIdentity']['userName']}")
            aws_user = data['userIdentity']['userName']
            break
        else:
            continue
        break


# If access key found, enumerate permissions for user
if aws_user:
    # Group details
    users_groups = parse_groups(iam_client.list_groups_for_user(UserName=aws_user))
    if users_groups:
        print(f"\nUser {aws_user} is a member of the following groups:")
        for g in users_groups:
            print(g)
    else:
        print(f"\nUser {aws_user} is not a member of any groups.")

    # Inline policy details
    users_inline_polices = parse_inline_polices(iam_client.list_user_policies(UserName=aws_user))
    if users_inline_polices:
        print(f"\nUser {aws_user} has the following inline polices:")
        for inline in users_inline_polices:
            print(inline)
    else:
        print(f"\nUser {aws_user} is not a has no inline polices.")

    # Managed Policy details
    users_attached_polices = parse_attached_polices(iam_client.list_attached_user_policies(UserName=aws_user))
    if users_attached_polices:
        print(f"\nUser {aws_user} has the following attached policies:")
        for attached in users_attached_polices:
            print(*attached, sep="\t")
    else:
        print(f"\nUser {aws_user} is not a has no attached polices.")
else:
    print(f"Access key {args.aws_access_key_id} not found.")
