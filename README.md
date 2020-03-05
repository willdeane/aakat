# aakat
### AWS Access Key Audit Tool
Use case: An AWS Access key has been found, e.g., in a git repo, temporary file, or environment variables and you need
to identify which user the access key is associated with. 

If the Access Key is active, you have both the access key ID and the secret key, and you have permission to use the keys
it's more efficient to use the AWS CLI instead:

`aws sts get-caller-identity`

`aakat` will first search all IAM users, if the key isn't associated with any user it will search the last 
90 days of CloudTrail logs for any event associated with the Access Key ID. 
 
If the AWS access key is found it prints:
1. The username
2. The names of any groups the user is a member of
3. The names of any inline polices associated with the user
4. The names of any polices attached to the user
5. Optionally the policy document json

### giUsage 
```python aakat.py [--aws-profile PROFILE] [--print-polices] aws_access_key_id ```


### Requirements
- Python 3.6 or greater
- AWS cli 
- boto3

#### To Do
1. Enumerate permission for groups and inline polices and optionally  print policy json
2. Produced 'consolidated' permission set by combining all permissions in all associated polices 
 