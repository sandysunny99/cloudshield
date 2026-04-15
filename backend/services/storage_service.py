import requests

def check_storage_public(provider, bucket):
    # PHASE 3: ADD DEMO FALLBACK
    if bucket in ["commoncrawl", "nyc-tlc"]:
        return {
            "public": True,
            "status": "Public (demo fallback)",
            "bucket": bucket,
            "provider": provider,
            "demo": True
        }

    try:
        if provider == "aws":
            url = f"http://{bucket}.s3.amazonaws.com"
        elif provider == "azure":
            url = f"https://{bucket}.blob.core.windows.net"
        elif provider == "gcp":
            url = f"https://storage.googleapis.com/{bucket}"
        else:
            return {"public": False, "error": "Invalid provider"}

        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return {
                "public": True,
                "status": "Publicly Accessible",
                "bucket": bucket,
                "provider": provider
            }
        else:
            return {
                "public": False,
                "status": "Not Public / Restricted",
                "bucket": bucket,
                "provider": provider
            }

    except requests.exceptions.RequestException:
        return {
            "public": False,
            "status": "Connection failed (handled safely)",
            "bucket": bucket,
            "provider": provider,
            "demo": True
        }
