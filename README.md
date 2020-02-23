# aakat
### Access Key Audit Tool
Use case: AWS Access key has been found, e.g., in a git repo, temporary file, or environment variables and you need
to identify which user the access key is associated with.

If the AWS access key is found it prints:
1. The username
2. The names of any groups the user is a member of
3. The names of any inline polices associated with the user
4. The names of any polices attached to the user




#### To Do
1. If access key isn't found - search cloudtrail for events related to access key ID 
2. Enumerate permission for groups, inline polices and attached polices
3. produced 'consolidated' permission set by combining all permissions in all associated polices 
 