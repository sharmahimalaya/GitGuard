#!/usr/bin/env python3
"""
Webhook Replay CLI Script
Sends a signed GitHub Pull Request webhook payload to the deployed API Gateway endpoint.
"""

import argparse
import hashlib
import hmac
import json
import sys
import time
import requests


def create_signed_payload(secret: str, repo: str, pr_number: int, commit_sha: str, installation_id: int):
    payload = {
        "action": "synchronize",
        "repository": {
            "full_name": repo,
            "name": repo.split("/")[-1] if "/" in repo else repo,
            "owner": {"login": repo.split("/")[0] if "/" in repo else "owner"}
        },
        "pull_request": {
            "number": pr_number,
            "head": {
                "sha": commit_sha,
                "ref": "feature/security-update"
            },
            "base": {
                "ref": "main"
            }
        },
        "installation": {
            "id": installation_id
        }
    }

    raw_body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = "sha256=" + hmac.new(secret.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
    
    return raw_body, signature


def main():
    parser = argparse.ArgumentParser(description="Replay a GitHub pull_request webhook payload to the deployed auditor endpoint.")
    parser.add_argument("--url", required=True, help="API Gateway /webhook endpoint URL")
    parser.add_argument("--secret", required=True, help="GitHub Webhook Secret")
    parser.add_argument("--repo", default="octocat/Hello-World", help="Repository full name (owner/repo)")
    parser.add_argument("--pr", type=int, default=1, help="Pull Request number")
    parser.add_argument("--sha", default="6dcb09b5b57875f334f61aebed695e2e4193db5e", help="Head commit SHA")
    parser.add_argument("--installation-id", type=int, default=12345678, help="GitHub App installation ID")

    args = parser.parse_args()

    delivery_id = f"test-replay-{int(time.time())}"
    raw_body, signature = create_signed_payload(
        secret=args.secret,
        repo=args.repo,
        pr_number=args.pr,
        commit_sha=args.sha,
        installation_id=args.installation_id
    )

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id,
        "X-Hub-Signature-256": signature,
        "User-Agent": "GitHub-Hookshot/replay-test"
    }

    print(f"📡 Sending mock webhook event to: {args.url}")
    print(f"📦 Repository: {args.repo} | PR #{args.pr} | Delivery: {delivery_id}")

    try:
        response = requests.post(args.url, data=raw_body, headers=headers, timeout=15)
        print(f"\nStatus Code: {response.status_code}")
        print("Response Body:")
        print(response.text)

        if response.status_code == 202:
            print("\n✅ Webhook successfully accepted and queued for worker processing!")
        elif response.status_code == 200:
            print("\nℹ️ Webhook processed (duplicate delivery or skipped event).")
        else:
            print(f"\n❌ Webhook rejected with status code {response.status_code}")
    except Exception as e:
        print(f"\n❌ Request failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
