"""
CloudShield – Multi-Cloud Storage Public Exposure Engine
PHASE 3: Hardened with HTTPS, timeout=5, allow_redirects, full try/except wrapping.
"""
import requests

def check_storage_public(provider: str, bucket: str) -> dict:
    """
    Safely checks whether a cloud storage bucket is publicly accessible.
    NEVER raises – always returns a structured dict.
    """
    if not provider or not bucket:
        return {"public": False, "error": "Missing provider or bucket", "status": "Invalid input", "provider": str(provider), "bucket": str(bucket)}

    provider = provider.lower().strip()
    bucket   = bucket.strip()

    # ── PHASE 3: Hardened HTTP check ──
    try:
        if provider == "aws":
            url = f"https://{bucket}.s3.amazonaws.com"
        elif provider == "azure":
            url = f"https://{bucket}.blob.core.windows.net"
        elif provider == "gcp":
            url = f"https://storage.googleapis.com/{bucket}"
        else:
            return {"public": False, "error": f"Unsupported provider: {provider}", "bucket": bucket, "provider": provider}

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "CloudShield-SecurityScanner/2.0"}
        )

        if response.status_code == 200:
            return {
                "public": True,
                "status": "Publicly Accessible",
                "bucket": bucket,
                "provider": provider,
                "http_status": response.status_code
            }
        elif response.status_code in (403, 401):
            return {
                "public": False,
                "status": "Access Denied (Private bucket)",
                "bucket": bucket,
                "provider": provider,
                "http_status": response.status_code
            }
        elif response.status_code == 404:
            return {
                "public": False,
                "status": "Bucket not found",
                "bucket": bucket,
                "provider": provider,
                "http_status": response.status_code
            }
        else:
            return {
                "public": False,
                "status": f"Not Public / Restricted (HTTP {response.status_code})",
                "bucket": bucket,
                "provider": provider,
                "http_status": response.status_code
            }

    except requests.exceptions.ConnectionError:
        return {
            "public": False,
            "status": "unknown",
            "message": "Connection error — network unreachable",
            "bucket": bucket,
            "provider": provider
        }
    except requests.exceptions.Timeout:
        return {
            "public": False,
            "status": "unknown",
            "message": "Connection error — request timed out",
            "bucket": bucket,
            "provider": provider
        }
    except requests.exceptions.RequestException as e:
        return {
            "public": False,
            "status": "unknown",
            "message": f"Connection error: {str(e)}",
            "bucket": bucket,
            "provider": provider
        }
    except Exception as e:
        return {
            "public": False,
            "status": "unknown",
            "message": f"Internal check error: {str(e)}",
            "bucket": bucket,
            "provider": provider
        }
