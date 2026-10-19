import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import jwt
import requests
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()

_secrets_client = None
_cached_secrets: Optional[Dict[str, Any]] = None
_cached_installation_tokens: Dict[int, Tuple[str, float]] = {}


def get_secrets_client():
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client("secretsmanager")
    return _secrets_client


def get_app_secrets() -> Dict[str, str]:
    """Retrieve app_id and private_key from Secrets Manager and cache in memory."""
    global _cached_secrets
    if _cached_secrets is not None:
        return _cached_secrets

    secret_arn = os.environ.get("GITHUB_SECRET_ARN")
    if not secret_arn:
        raise ValueError("GITHUB_SECRET_ARN environment variable is not configured.")

    client = get_secrets_client()
    resp = client.get_secret_value(SecretId=secret_arn)
    secret_str = resp.get("SecretString")
    if not secret_str:
        raise ValueError("SecretString is empty in Secrets Manager.")

    secret_data = json.loads(secret_str)
    if "app_id" not in secret_data or "private_key" not in secret_data:
        raise ValueError("Secret must contain 'app_id' and 'private_key'.")

    _cached_secrets = secret_data
    return _cached_secrets


def get_app_jwt(app_id: str, private_key_pem: str) -> str:
    """Generate a short-lived GitHub App RS256 JWT valid for 10 minutes."""
    now = int(time.time())
    payload = {
        "iat": now - 60,  # 1 min in past for clock skew
        "exp": now + (10 * 60),  # 10 minutes validity
        "iss": str(app_id),
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def get_installation_token(installation_id: int) -> str:
    """
    Exchange App JWT for an installation access token.
    Caches token in-memory until near expiration.
    """
    now = time.time()
    if installation_id in _cached_installation_tokens:
        token, expires_at = _cached_installation_tokens[installation_id]
        if now < expires_at - 120:  # 2 minute safety margin
            return token

    secrets = get_app_secrets()
    app_id = secrets["app_id"]
    private_key = secrets["private_key"]
    app_jwt = get_app_jwt(app_id, private_key)

    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    resp = requests.post(url, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    token = data["token"]
    # GitHub installation tokens are valid for 1 hour (3600 seconds)
    _cached_installation_tokens[installation_id] = (token, now + 3500)
    return token


def _handle_rate_limits(response: requests.Response):
    """Check remaining rate limits and log/backoff if near exhaustion."""
    remaining = response.headers.get("X-RateLimit-Remaining")
    reset_time = response.headers.get("X-RateLimit-Reset")
    if remaining is not None and int(remaining) < 5 and reset_time is not None:
        sleep_sec = max(1, int(reset_time) - int(time.time()))
        if sleep_sec < 10:  # Only sleep if brief
            logger.warning(f"GitHub Rate limit low ({remaining} remaining). Sleeping {sleep_sec}s")
            time.sleep(sleep_sec)


def get_pr_files(repo_full_name: str, pr_number: int, installation_id: int) -> List[Dict[str, Any]]:
    """
    Fetch all changed files in a PR using pagination.
    Returns list of file metadata objects with 'filename', 'status', 'patch', etc.
    """
    token = get_installation_token(installation_id)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    files: List[Dict[str, Any]] = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files"
        params = {"page": page, "per_page": per_page}
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        _handle_rate_limits(resp)
        resp.raise_for_status()

        page_files = resp.json()
        if not page_files:
            break

        files.extend(page_files)
        if len(page_files) < per_page:
            break
        page += 1

    return files


def post_pull_request_review(
    repo_full_name: str,
    pr_number: int,
    commit_sha: str,
    installation_id: int,
    body: str,
    comments: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Post a single consolidated PR review with optional inline comments.
    If posting with inline comments fails due to line validity (422), falls back to
    posting comments inside the main summary review body.
    """
    token = get_installation_token(installation_id)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/reviews"

    payload: Dict[str, Any] = {
        "commit_id": commit_sha,
        "event": "COMMENT",
        "body": body,
    }
    if comments:
        payload["comments"] = comments

    resp = requests.post(url, headers=headers, json=payload, timeout=15)
    _handle_rate_limits(resp)

    # Fallback if inline comments failed on line positioning (HTTP 422)
    if resp.status_code == 422 and comments:
        logger.warning(f"GitHub review creation returned 422. Retrying with comments embedded in summary body.")
        fallback_body = body + "\n\n### ⚠️ Inline Review Comments (Fallback List)\n\n"
        for c in comments:
            fallback_body += f"- **File:** `{c.get('path')}` (Line {c.get('line')})\n{c.get('body')}\n\n"
        
        fallback_payload = {
            "commit_id": commit_sha,
            "event": "COMMENT",
            "body": fallback_body,
        }
        resp = requests.post(url, headers=headers, json=fallback_payload, timeout=15)
        _handle_rate_limits(resp)

    resp.raise_for_status()
    return resp.json()
