import boto3
import argparse
import re


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

# Create IAM client/ resource
if args.profile:
    boto3.setup_default_session(profile_name=args.profile)
iam_client = boto3.client('iam')
iam_resource = boto3.resource('iam')

aws_user = None
for user in iam_resource.users.all():
    for key in user.access_keys.all():
        if args.aws_access_key_id == key.id:
            print("Access Key ID {0} belongs user to user {1}".format(key.id, key.user_name))
            aws_user = key.user_name

# If access key found, enumerate permissions for user
if aws_user:
    # aws_inline_polices = iam_client.list_user_policies(UserName=aws_user)
    #aws_managed_polices = iam_client.list_attached_user_policies(UserName=aws_user)

    # Group details
    users_groups = parse_groups(iam_client.list_groups_for_user(UserName=aws_user))
    if users_groups:
        print("\nUser {0} is a member of the following groups:".format(aws_user))
        for g in users_groups:
            print(g)

    # Inline policy details
    users_inline_polices = parse_inline_polices(iam_client.list_user_policies(UserName=aws_user))
    if users_inline_polices:
        print("\nUser {0} has the following inline polices attached".format(aws_user))
        for inline in users_inline_polices:
            print(inline)

    # Managed Policy details
    users_attached_polices = parse_attached_polices(iam_client.list_attached_user_policies(UserName=aws_user))
    if users_attached_polices:
        print("\nUser {0} has the following policies attached".format(aws_user))
        for attached in users_attached_polices:
            print(*attached, sep="\t")
else:
    print("Access key {0} not found.".format(args.aws_access_key_id))
