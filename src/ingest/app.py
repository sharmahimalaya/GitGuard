import base64
import hmac
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Lazy clients & cached secret
_secrets_client = None
_dynamodb_resource = None
_lambda_client = None
_cached_webhook_secret: Optional[str] = None


def get_secrets_client():
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client("secretsmanager")
    return _secrets_client


def get_dynamodb_table():
    global _dynamodb_resource
    if _dynamodb_resource is None:
        _dynamodb_resource = boto3.resource("dynamodb")
    return _dynamodb_resource.Table(os.environ["TABLE_NAME"])


def get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda")
    return _lambda_client


def get_webhook_secret() -> str:
    """Fetch webhook secret from AWS Secrets Manager and cache in-memory across warm starts."""
    global _cached_webhook_secret
    if _cached_webhook_secret is not None:
        return _cached_webhook_secret

    secret_arn = os.environ.get("GITHUB_SECRET_ARN")
    if not secret_arn:
        raise ValueError("GITHUB_SECRET_ARN environment variable is not configured.")

    client = get_secrets_client()
    resp = client.get_secret_value(SecretId=secret_arn)
    secret_str = resp.get("SecretString")
    if not secret_str:
        raise ValueError("SecretString is empty in Secrets Manager.")

    secret_data = json.loads(secret_str)
    webhook_sec = secret_data.get("webhook_secret")
    if not webhook_sec:
        raise ValueError("'webhook_secret' key not found in Secrets Manager secret JSON.")

    _cached_webhook_secret = webhook_sec
    return _cached_webhook_secret


def verify_signature(secret: str, raw_body_bytes: bytes, signature_header: Optional[str]) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature using constant-time comparison."""
    if not signature_header:
        logger.warning("Missing X-Hub-Signature-256 header")
        return False

    prefix = "sha256="
    if not signature_header.startswith(prefix):
        logger.warning("Invalid X-Hub-Signature-256 format (expected sha256= prefix)")
        return False

    expected_sig = signature_header[len(prefix):].strip()
    computed_sig = hmac.new(
        key=secret.encode("utf-8"),
        msg=raw_body_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(computed_sig, expected_sig)


def record_idempotency_delivery(table, delivery_id: str) -> bool:
    """
    Attempt conditional write for X-GitHub-Delivery.
    Returns True if successfully written (new delivery), False if duplicate.
    """
    ttl = int(time.time()) + 86400  # 24 hours retention
    try:
        table.put_item(
            Item={
                "PK": f"delivery#{delivery_id}",
                "SK": "delivery",
                "ttl": ttl,
                "created_at": int(time.time()),
            },
            ConditionExpression="attribute_not_exists(PK)"
        )
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info("Duplicate delivery detected (idempotent skip)", extra={"delivery_id": delivery_id})
            return False
        logger.error(f"DynamoDB error recording delivery: {e}")
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Ingest Lambda entrypoint.
    Verifies signature, filters pull_request actions, records delivery idempotency,
    and invokes the worker Lambda asynchronously.
    """
    # 1. Normalize headers (case-insensitive lookup)
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    signature_header = headers.get("x-hub-signature-256")
    event_type = headers.get("x-github-event")
    delivery_id = headers.get("x-github-delivery", "")

    # 2. Extract raw body bytes
    raw_body = event.get("body", "")
    if event.get("isBase64Encoded", False):
        raw_body_bytes = base64.b64decode(raw_body)
    else:
        raw_body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body

    # 3. Verify Signature
    try:
        secret = get_webhook_secret()
    except Exception as e:
        logger.error(f"Failed to load webhook secret: {e}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Configuration error"})
        }

    if not verify_signature(secret, raw_body_bytes, signature_header):
        logger.warning("Unauthorized webhook: signature verification failed")
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Invalid signature"})
        }

    # 4. Filter events: only pull_request
    if event_type != "pull_request":
        logger.info(f"Ignoring non-pull_request event: {event_type}")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"message": f"Ignored event type '{event_type}'"})
        }

    try:
        body_json = json.loads(raw_body_bytes.decode("utf-8"))
    except Exception as e:
        logger.error(f"Failed to parse JSON body: {e}")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Malformed JSON payload"})
        }

    # 5. Filter PR actions
    action = body_json.get("action")
    allowed_actions = {"opened", "synchronize", "reopened"}
    if action not in allowed_actions:
        logger.info(f"Ignoring pull_request action: {action}")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"message": f"Ignored pull_request action '{action}'"})
        }

    # 6. Idempotency Check
    if delivery_id:
        table = get_dynamodb_table()
        is_new = record_idempotency_delivery(table, delivery_id)
        if not is_new:
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"message": "Duplicate delivery ignored"})
            }

    # 7. Extract minimal payload
    repo_info = body_json.get("repository", {})
    repo_full_name = repo_info.get("full_name")
    pr_info = body_json.get("pull_request", {})
    pr_number = pr_info.get("number")
    head_sha = pr_info.get("head", {}).get("sha")
    installation = body_json.get("installation", {})
    installation_id = installation.get("id")

    if not all([repo_full_name, pr_number, head_sha, installation_id]):
        logger.error("Missing required PR payload fields", extra={
            "repo_full_name": repo_full_name,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "installation_id": installation_id
        })
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Missing required fields in webhook payload"})
        }

    worker_payload = {
        "repo_full_name": repo_full_name,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "installation_id": installation_id,
        "delivery_id": delivery_id
    }

    # 8. Asynchronously invoke Worker Lambda
    worker_arn = os.environ.get("WORKER_FUNCTION_ARN")
    if not worker_arn:
        logger.error("WORKER_FUNCTION_ARN not set")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Worker ARN not configured"})
        }

    lambda_client = get_lambda_client()
    try:
        lambda_client.invoke(
            FunctionName=worker_arn,
            InvocationType="Event",
            Payload=json.dumps(worker_payload)
        )
        logger.info("Successfully queued Worker invocation", extra={"pr": f"{repo_full_name}#{pr_number}"})
    except Exception as e:
        logger.error(f"Failed to invoke Worker Lambda: {e}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Failed to trigger scan worker"})
        }

    return {
        "statusCode": 202,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "Audit scan queued"})
    }
