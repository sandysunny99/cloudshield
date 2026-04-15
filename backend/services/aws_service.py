"""
CloudShield AWS Service
REAL live AWS integration via boto3.
Translates AWS API responses into CloudShield's unified cloud-config JSON format.
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError

def get_boto_session():
    """Returns a valid Boto3 session if credentials exist."""
    session = boto3.Session()
    # verify credentials
    if not session.get_credentials():
        return None
    return session

def fetch_s3_data(session):
    """Fetch S3 buckets and their public access blocks."""
    s3_client = session.client('s3')
    result = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get('Buckets', []):
            name = bucket['Name']
            
            # check public access block
            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                is_public = not (pab['PublicAccessBlockConfiguration'].get('IgnorePublicAcls') 
                                 and pab['PublicAccessBlockConfiguration'].get('RestrictPublicBuckets'))
            except ClientError as e:
                if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                    is_public = True # No block -> exposed
                else:
                    is_public = False
            
            # get acl
            try:
                acl_data = s3_client.get_bucket_acl(Bucket=name)
                acl_str = 'private'
                for grant in acl_data.get('Grants', []):
                    if grant.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        acl_str = 'public-read'
                        break
            except ClientError:
                acl_str = 'private'

            # encryption
            try:
                enc = s3_client.get_bucket_encryption(Bucket=name)
                encryption_enabled = True
            except ClientError:
                encryption_enabled = False

            # logging
            try:
                log = s3_client.get_bucket_logging(Bucket=name)
                logging_enabled = 'LoggingEnabled' in log
            except ClientError:
                logging_enabled = False

            result.append({
                "name": name,
                "public": is_public,
                "acl": acl_str,
                "encryption": {"enabled": encryption_enabled},
                "logging": {"enabled": logging_enabled}
            })
    except (ClientError, BotoCoreError) as e:
        print(f"[AWS] S3 fetch error: {e}")
    return result

def fetch_iam_data(session):
    """Fetch IAM roles and their inline/attached policies."""
    iam_client = session.client('iam')
    result = []
    try:
        # Limited to 50 for quick scanning
        roles = iam_client.list_roles(MaxItems=50)
        for role in roles.get('Roles', []):
            name = role['RoleName']
            policies = []
            
            # Attached policies
            try:
                attached = iam_client.list_attached_role_policies(RoleName=name)
                for ap in attached.get('AttachedPolicies', []):
                    pol_ver = iam_client.get_policy(PolicyArn=ap['PolicyArn'])
                    doc = iam_client.get_policy_version(
                        PolicyArn=ap['PolicyArn'], 
                        VersionId=pol_ver['Policy']['DefaultVersionId']
                    )
                    statements = doc['PolicyVersion']['Document'].get('Statement', [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get('Effect') == 'Allow':
                            action = stmt.get('Action', '')
                            resource = stmt.get('Resource', '')
                            if isinstance(action, list): action = action[0] if action else ""
                            if isinstance(resource, list): resource = resource[0] if resource else ""
                            policies.append({"name": ap['PolicyName'], "action": action, "resource": resource})
            except ClientError:
                pass
            
            mfa_req = False
            assume_doc = role.get('AssumeRolePolicyDocument', {})
            statements = assume_doc.get('Statement', [])
            if isinstance(statements, dict): statements = [statements]
            for stmt in statements:
                if 'Condition' in stmt and 'Bool' in stmt['Condition']:
                    if stmt['Condition']['Bool'].get('aws:MultiFactorAuthPresent') == 'true':
                        mfa_req = True
            
            result.append({
                "name": name,
                "mfa_required": mfa_req,
                "policies": policies
            })
    except (ClientError, BotoCoreError) as e:
        print(f"[AWS] IAM fetch error: {e}")
    return result

def fetch_ec2_security_groups(session):
    """Fetch EC2 security groups and their ingress rules."""
    ec2_client = session.client('ec2', region_name='us-east-1') # Default region
    result = []
    try:
        sgs = ec2_client.describe_security_groups(MaxResults=50)
        for sg in sgs.get('SecurityGroups', []):
            name = sg.get('GroupName', 'unknown')
            ingress_rules = []
            for perm in sg.get('IpPermissions', []):
                proto = perm.get('IpProtocol', 'tcp')
                port = perm.get('FromPort', 'any')
                for r in perm.get('IpRanges', []):
                    cidr = r.get('CidrIp')
                    ingress_rules.append({
                        "protocol": proto,
                        "port": port,
                        "cidr": cidr
                    })
            result.append({
                "name": name,
                "id": sg.get('GroupId'),
                "ingress_rules": ingress_rules
            })
    except (ClientError, BotoCoreError) as e:
        print(f"[AWS] EC2 SG fetch error: {e}")
    return result


def generate_live_cloud_config() -> dict:
    """
    Auto-fetches live AWS data if credentials exist.
    Returns a unified JSON structure for the OPA engine.
    """
    session = get_boto_session()
    if not session:
        return None  # No credentials
        
    print("[AWS] Live credentials detected. Fetching cloud state...")
    
    config = {
        "resource_type": "aws_environment",
        "s3_buckets": fetch_s3_data(session),
        "iam_roles": fetch_iam_data(session),
        "security_groups": fetch_ec2_security_groups(session),
        "containers": [],     # Can be extended to ECS/EKS
        "rds_instances": [],  # Can be extended to RDS
        "vpcs": []            # Can be extended to VPC
    }
    
    return config
