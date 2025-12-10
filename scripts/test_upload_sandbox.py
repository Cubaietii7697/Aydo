import argparse
import hashlib
import json
import os
import secrets
import string
import sys
import tempfile
import time
from pathlib import Path

import requests


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def post_json(
    url: str, payload: dict, headers: dict | None = None, timeout: int = 10
) -> requests.Response:
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    return requests.post(url, headers=hdrs, data=json.dumps(payload), timeout=timeout)


def register(base_url: str, email: str, nickname: str, password: str) -> requests.Response:
    return post_json(
        f"{base_url}/api/auth/register",
        {"email": email, "nickname": nickname, "password": password},
    )


def login(base_url: str, email: str, password: str) -> requests.Response:
    return post_json(
        f"{base_url}/api/auth/login",
        {"email": email, "password": password},
    )


def request_scan(base_url: str, token: str, file_hash: str, runtime: int) -> requests.Response:
    return post_json(
        f"{base_url}/api/sandbox/request-file-scan",
        {"fileHash": file_hash, "runtime": runtime},
        headers={"Authorization": f"Bearer {token}"},
    )


def upload_file(base_url: str, token: str, file_hash: str, file_path: Path) -> requests.Response:
    url = f"{base_url}/api/sandbox/upload-file"
    headers = {"Authorization": f"Bearer {token}"}
    with file_path.open("rb") as f:
        files = {"file": (file_path.name, f)}
        data = {"fileHash": file_hash}
        return requests.post(url, headers=headers, files=files, data=data, timeout=30)


def make_random_file(size_kb: int = 4) -> Path:
    fd, path_str = tempfile.mkstemp(prefix="aydo_test_", suffix=".bin")
    path = Path(path_str)
    with os.fdopen(fd, "wb") as f:
        f.write(secrets.token_bytes(size_kb * 1024))
    return path


def generate_password(length: int = 12) -> str:
    if length < 8:
        length = 8
    rng = secrets.SystemRandom()
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    alphabet = lowers + uppers + digits
    password_chars = [
        rng.choice(lowers),
        rng.choice(uppers),
        rng.choice(digits),
    ]
    password_chars.extend(rng.choice(alphabet) for _ in range(length - len(password_chars)))
    rng.shuffle(password_chars)
    return "".join(password_chars)


def poll_scan_status(
    base_url: str,
    token: str,
    file_hash: str,
    runtime: int,
    interval_s: float,
    timeout_s: float,
) -> None:
    url = f"{base_url}/api/sandbox/request-file-scan"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"fileHash": file_hash, "runtime": runtime}
    deadline = time.time() + timeout_s

    print(f"[poll] Watching status every {interval_s}s (timeout {timeout_s}s)...")

    while time.time() < deadline:
        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=10)
        try:
            body = resp.json()
        except Exception:
            body = resp.text

        print(f"[poll] status={resp.status_code} body={body}")

        if resp.status_code in (200, 201) and isinstance(body, dict):
            status = body.get("status")
            virus_type = body.get("virusType")
            score = body.get("score")
            if status in {"Completed", "Failed"}:
                print(
                    f"[poll] Final status={status} virusType={virus_type} score={score}"
                )
                return

        time.sleep(interval_s)

    print(f"[poll] Timed out after {timeout_s} seconds without completion.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fully automated Sandbox upload test (register, login, scan, upload)."
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:80",
        help="Server base URL (default: http://localhost:80)",
    )
    parser.add_argument(
        "--runtime", type=int, default=60, help="Runtime seconds for the scan (default: 60)"
    )
    parser.add_argument(
        "--size-kb", type=int, default=4, help="Random file size in KB (default: 4)"
    )
    parser.add_argument(
        "--status-interval",
        type=float,
        default=5.0,
        help="Seconds between status polls (default: 5)",
    )
    parser.add_argument(
        "--status-timeout",
        type=float,
        default=180.0,
        help="Max seconds to wait for completion (default: 180)",
    )
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    # Generate random credentials
    token_part = secrets.token_hex(6)
    email = f"auto_{token_part}@example.test"
    nickname = f"User{secrets.choice(string.ascii_uppercase)}{secrets.choice(string.ascii_lowercase)}{secrets.choice(string.ascii_uppercase)}"
    password = generate_password()

    print(f"[info] Registering user {email} ...")
    reg_resp = register(base_url, email, nickname, password)
    print(f"[register] status={reg_resp.status_code}")
    try:
        print(reg_resp.json())
    except Exception:
        print(reg_resp.text)

    if reg_resp.status_code >= 400 and reg_resp.status_code != 409:
        print("[error] Registration failed; aborting.")
        sys.exit(1)

    print("[info] Logging in ...")
    login_resp = login(base_url, email, password)
    print(f"[login] status={login_resp.status_code}")
    try:
        login_body = login_resp.json()
        print(login_body)
    except Exception:
        print(login_resp.text)
        sys.exit(1)

    if "accessToken" not in login_body:
        print("[error] No accessToken received; aborting.")
        sys.exit(1)
    access_token = login_body["accessToken"]

    # Create random file
    temp_file = make_random_file(args.size_kb)
    print(f"[info] Generated random file: {temp_file} ({args.size_kb} KB)")

    try:
        file_hash = sha256_file(temp_file)
        print(f"[info] fileHash={file_hash}")

        print("[info] Requesting scan ...")
        scan_resp = request_scan(base_url, access_token, file_hash, args.runtime)
        print(f"[request-scan] status={scan_resp.status_code}")
        try:
            print(scan_resp.json())
        except Exception:
            print(scan_resp.text)

        if scan_resp.status_code >= 400:
            print("[error] Scan request failed; aborting.")
            sys.exit(1)

        print("[info] Uploading file ...")
        upload_resp = upload_file(base_url, access_token, file_hash, temp_file)
        print(f"[upload] status={upload_resp.status_code}")
        try:
            print(upload_resp.json())
        except Exception:
            print(upload_resp.text)

        if upload_resp.status_code < 400:
            poll_scan_status(
                base_url,
                access_token,
                file_hash,
                args.runtime,
                args.status_interval,
                args.status_timeout,
            )

    finally:
        try:
            temp_file.unlink()
            print(f"[cleanup] removed {temp_file}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
