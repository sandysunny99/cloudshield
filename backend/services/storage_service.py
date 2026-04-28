"""
CloudShield – Multi-Cloud Storage Public Exposure Engine
Real implementation using three detection methods for AWS S3:
  1. Block Public Access settings (modern AWS control — overrides everything)
  2. Bucket ACL (grants to AllUsers / AuthenticatedUsers)
  3. Bucket Policy (Statement with Principal: *)

For Azure/GCP: HTTP probe (unauthenticated GET returns 200 = public).
No mock data. No demo flags. All results are real.
"""
import json
import requests
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.config import Config

_S3_TIMEOUT = Config(connect_timeout=5, read_timeout=5)


def check_storage_public(provider: str, bucket: str) -> dict:
    """
    Check whether a cloud storage bucket is publicly accessible.
    Never raises — always returns a structured dict.
    """
    if not provider or not bucket:
        return {
            "public": False,
            "error": "Missing provider or bucket",
            "status": "Invalid input",
            "provider": str(provider),
            "bucket": str(bucket)
        }

    provider = provider.lower().strip()
    bucket = bucket.strip()

    if provider == "aws":
        return _check_aws_s3(bucket)
    elif provider in ("azure", "gcp"):
        return _check_http_probe(provider, bucket)
    else:
        return {
            "public": False,
            "error": f"Unsupported provider: {provider}",
            "status": "Unsupported",
            "provider": provider,
            "bucket": bucket
        }


def _check_aws_s3(bucket: str) -> dict:
    """
    Three-method AWS S3 public access check.
    Uses real Boto3 API calls — requires AWS credentials in environment.
    """
    try:
        s3 = boto3.client("s3", config=_S3_TIMEOUT)

        # ── METHOD 1: Block Public Access (most authoritative) ──
        # If ALL four BPA settings are True, the bucket is guaranteed private
        # regardless of ACL or bucket policy.
        try:
            bpa_resp = s3.get_public_access_block(Bucket=bucket)
            cfg = bpa_resp.get("PublicAccessBlockConfiguration", {})
            all_blocked = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
            if all_blocked:
                return {
                    "public": False,
                    "status": "Private",
                    "reason": "Block Public Access is fully enabled (all 4 settings ON)",
                    "method": "block_public_access",
                    "provider": "aws",
                    "bucket": bucket
                }
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                pass  # No BPA config — continue to ACL/policy checks
            elif code in ("AccessDenied", "403"):
                return {
                    "public": False,
                    "status": "Access Denied",
                    "reason": "Insufficient permissions to read BPA config (likely private)",
                    "method": "block_public_access",
                    "provider": "aws",
                    "bucket": bucket
                }
            elif code == "NoSuchBucket":
                return {
                    "public": False,
                    "status": "Not Found",
                    "reason": "Bucket does not exist",
                    "provider": "aws",
                    "bucket": bucket
                }
            # Other errors: continue to ACL check

        # ── METHOD 2: ACL check ──
        acl_public = False
        acl_reason = ""
        try:
            acl = s3.get_bucket_acl(Bucket=bucket)
            PUBLIC_URIS = {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            }
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if uri in PUBLIC_URIS:
                    acl_public = True
                    acl_reason = f"ACL grants {grant.get('Permission','READ')} to {uri.split('/')[-1]}"
                    break
        except ClientError:
            pass  # ACL read may be denied — not conclusive

        # ── METHOD 3: Bucket Policy ──
        policy_public = False
        policy_reason = ""
        try:
            pol_resp = s3.get_bucket_policy(Bucket=bucket)
            policy_doc = json.loads(pol_resp.get("Policy", "{}"))
            for stmt in policy_doc.get("Statement", []):
                effect = stmt.get("Effect", "")
                principal = stmt.get("Principal")
                if effect == "Allow" and principal in ("*", {"AWS": "*"}):
                    policy_public = True
                    policy_reason = "Bucket policy grants public Allow to Principal '*'"
                    break
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                pass  # Other errors are non-conclusive

        is_public = acl_public or policy_public
        reasons = [r for r in [acl_reason, policy_reason] if r]

        return {
            "public": is_public,
            "status": "Public" if is_public else "Private",
            "reason": "; ".join(reasons) if reasons else "No public ACL grants or policy statements found",
            "method": "acl+policy",
            "provider": "aws",
            "bucket": bucket
        }

    except NoCredentialsError:
        return {
            "public": False,
            "status": "No Credentials",
            "error": "AWS credentials not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.",
            "provider": "aws",
            "bucket": bucket
        }
    except Exception as e:
        return {
            "public": False,
            "status": "Error",
            "error": str(e),
            "provider": "aws",
            "bucket": bucket
        }


def _check_http_probe(provider: str, bucket: str) -> dict:
    """
    HTTP probe for Azure Blob Storage and GCP Cloud Storage.
    A 200 response to an unauthenticated GET means the bucket is publicly accessible.
    """
    if provider == "azure":
        url = f"https://{bucket}.blob.core.windows.net"
    else:  # gcp
        url = f"https://storage.googleapis.com/{bucket}"

    try:
        resp = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "CloudShield-SecurityScanner/3.0"}
        )
        if resp.status_code == 200:
            return {
                "public": True,
                "status": "Public",
                "reason": f"Unauthenticated HTTP GET returned 200",
                "http_status": resp.status_code,
                "provider": provider,
                "bucket": bucket
            }
        elif resp.status_code in (403, 401):
            return {
                "public": False,
                "status": "Private",
                "reason": "Access denied (authentication required)",
                "http_status": resp.status_code,
                "provider": provider,
                "bucket": bucket
            }
        elif resp.status_code == 404:
            return {
                "public": False,
                "status": "Not Found",
                "reason": "Bucket not found",
                "http_status": resp.status_code,
                "provider": provider,
                "bucket": bucket
            }
        else:
            return {
                "public": False,
                "status": f"Restricted (HTTP {resp.status_code})",
                "http_status": resp.status_code,
                "provider": provider,
                "bucket": bucket
            }
    except requests.exceptions.Timeout:
        return {"public": False, "status": "Timeout", "error": "Connection timed out", "provider": provider, "bucket": bucket}
    except requests.exceptions.ConnectionError:
        return {"public": False, "status": "Unreachable", "error": "Network error", "provider": provider, "bucket": bucket}
    except Exception as e:
        return {"public": False, "status": "Error", "error": str(e), "provider": provider, "bucket": bucket}
