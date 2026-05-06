"""
R2 storage helper for DropSync agent.
Used to fetch/re-upload encrypted drop images during move operations.
"""

import os
import time
import uuid
import urllib.request

import boto3
from botocore.config import Config

R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "")
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "dropsync-files")
R2_PUBLIC_URL = os.getenv("R2_PUBLIC_URL", "")


def get_r2_client():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        region_name="auto",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=Config(signature_version="s3v4"),
    )


def upload_to_r2(data: str) -> dict:
    """Upload encrypted string data to R2. Returns {url, key}."""
    key = f"drops/{int(time.time())}-{uuid.uuid4()}"
    client = get_r2_client()
    client.put_object(
        Bucket=R2_BUCKET_NAME,
        Key=key,
        Body=data.encode("utf-8"),
        ContentType="application/octet-stream",
    )
    url = f"{R2_PUBLIC_URL}/{key}"
    return {"url": url, "key": key}


def delete_from_r2(key: str):
    """Delete an object from R2."""
    client = get_r2_client()
    client.delete_object(Bucket=R2_BUCKET_NAME, Key=key)


def fetch_from_r2(url: str) -> str | None:
    """Fetch encrypted data from an R2 URL."""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        import sys
        sys.stderr.write(f"R2 fetch failed: {e}\n")
        sys.stderr.flush()
        return None


def fetch_from_r2_by_key(key: str) -> str | None:
    """Fetch encrypted data from R2 using S3 API (no public URL needed)."""
    try:
        client = get_r2_client()
        response = client.get_object(Bucket=R2_BUCKET_NAME, Key=key)
        return response["Body"].read().decode("utf-8")
    except Exception as e:
        import sys
        sys.stderr.write(f"[r2] S3 fetch failed for key {key}: {e}\n")
        sys.stderr.flush()
        return None
