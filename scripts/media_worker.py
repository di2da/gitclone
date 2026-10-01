#!/usr/bin/env python3
"""Process DK Admin media jobs with OmniGet's managed yt-dlp engine."""

from __future__ import annotations

import json
import os
from pathlib import Path
import ipaddress
import re
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen
import zipfile


BASE_URL = os.environ.get("DOCMAGIC_MEDIA_BASE_URL", "https://invoice.dancekingdom.com.hk").rstrip("/")
TOKEN_FILE = Path(
    os.environ.get(
        "DOCMAGIC_MEDIA_WORKER_TOKEN_FILE",
        str(Path.home() / ".openclaw" / "secrets" / "dk-media-worker-token"),
    )
)
OMNIGET_YTDLP = Path(
    os.environ.get(
        "OMNIGET_YTDLP",
        str(Path.home() / "Library" / "Application Support" / "wtf.tonho.omniget" / "bin" / "yt-dlp"),
    )
)
VERCEL_BIN = os.environ.get("VERCEL_BIN") or shutil.which("vercel") or "/usr/local/bin/vercel"
BLOB_TOKEN_FILE = Path(
    os.environ.get(
        "DOCMAGIC_MEDIA_BLOB_TOKEN_FILE",
        str(Path.home() / ".openclaw" / "secrets" / "dk-media-blob-token"),
    )
)
WORKER_ID = os.environ.get("DOCMAGIC_MEDIA_WORKER_ID", f"{socket.gethostname()}-{os.getpid()}")
POLL_SECONDS = max(10, int(os.environ.get("DOCMAGIC_MEDIA_POLL_SECONDS", "30")))
ONCE = os.environ.get("DOCMAGIC_MEDIA_WORKER_ONCE", "").strip() == "1"
DRY_RUN = os.environ.get("DOCMAGIC_MEDIA_DRY_RUN", "").strip() == "1"
MAX_OUTPUT_BYTES = 250 * 1024 * 1024
WORK_ROOT = Path(
    os.environ.get(
        "DOCMAGIC_MEDIA_WORK_ROOT",
        str(Path.home() / ".openclaw" / "workspace" / "media-worker-tmp"),
    )
)


def _token() -> str:
    env_token = os.environ.get("DOCMAGIC_MEDIA_WORKER_TOKEN", "").strip()
    if env_token:
        return env_token
    try:
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _post_json(path: str, payload: dict[str, Any], attempts: int = 1) -> dict[str, Any]:
    token = _token()
    if not token:
        raise RuntimeError(f"Missing worker token: {TOKEN_FILE}")
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    last_error: Exception | None = None
    for attempt in range(attempts):
        request = Request(
            f"{BASE_URL}{path}",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "DK-OmniGet-Worker/1.0",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8") or "{}")
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(min(10, 2 ** attempt))
    raise RuntimeError(f"API request failed: {last_error}")


def _run(command: list[str], timeout: int = 3600, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    if extra_env:
        env.update(extra_env)
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        detail = ((exc.stderr or exc.stdout or "外部工具執行失敗").strip())[-800:]
        raise RuntimeError(detail) from exc


def _ensure_public_host(source_url: str) -> None:
    from urllib.parse import urlparse

    host = (urlparse(source_url).hostname or "").strip().lower()
    if not host:
        raise RuntimeError("連結缺少有效主機名稱。")
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError("未能解析連結主機。") from exc
    for address in {item[4][0] for item in addresses}:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise RuntimeError("基於安全理由，內聯網或本機連結不會處理。")


def _download(job: dict[str, Any], folder: Path) -> tuple[Path, str]:
    _ensure_public_host(str(job["source_url"]))
    output_template = str(folder / "%(title).160B [%(id)s].%(ext)s")
    common = [
        str(OMNIGET_YTDLP),
        "--no-update",
        "--no-playlist",
        "--max-filesize",
        "250M",
        "--output",
        output_template,
    ]
    if job["output_format"] == "mp4":
        command = common + ["--format", "bv*+ba/b", "--merge-output-format", "mp4", job["source_url"]]
        wanted_suffix = ".mp4"
    else:
        command = common + [
            "--extract-audio",
            "--audio-format",
            "mp3",
            "--audio-quality",
            "0",
            "--embed-metadata",
            job["source_url"],
        ]
        wanted_suffix = ".mp3"
    _run(command)
    candidates = [path for path in folder.iterdir() if path.is_file() and path.suffix.lower() == wanted_suffix]
    if not candidates:
        raise RuntimeError(f"OmniGet did not produce a {wanted_suffix} file")
    output = max(candidates, key=lambda item: item.stat().st_mtime)
    if output.stat().st_size > MAX_OUTPUT_BYTES:
        raise RuntimeError("輸出檔案超過 250 MB，未能上載。")
    title = output.stem.rsplit(" [", 1)[0].strip() or output.stem
    return output, title


def _delivery_file(output: Path, output_format: str) -> Path:
    if output_format != "mp3":
        return output
    archive = output.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(output, arcname=output.name)
    return archive


def _blob_token() -> str:
    value = os.environ.get("BLOB_READ_WRITE_TOKEN", "").strip()
    if value:
        return value
    try:
        return BLOB_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _upload_private_blob(job_token: str, media_path: Path) -> str:
    if DRY_RUN:
        return f"media/{job_token}/{media_path.name}"
    token = _blob_token()
    if not token:
        raise RuntimeError(f"Missing Blob token: {BLOB_TOKEN_FILE}")
    pathname = f"media/{job_token}/{media_path.name}"
    result = _run(
        [
            VERCEL_BIN,
            "blob",
            "put",
            str(media_path),
            "--access",
            "private",
            "--pathname",
            pathname,
            "--allow-overwrite",
            "true",
            "--multipart",
            "true",
            "--cache-control-max-age",
            "0",
            "--no-color",
        ],
        timeout=1800,
        extra_env={"BLOB_READ_WRITE_TOKEN": token},
    )
    cli_output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    match = re.search(r"https://[^\s]+\.private\.blob\.vercel-storage\.com/[^\s]+", cli_output)
    if not match:
        raise RuntimeError("Vercel Blob upload completed without a pathname")
    return unquote(urlparse(match.group(0)).path.lstrip("/"))


def _delete_private_blob(pathname: str) -> None:
    token = _blob_token()
    if not token:
        raise RuntimeError(f"Missing Blob token: {BLOB_TOKEN_FILE}")
    _run(
        [VERCEL_BIN, "blob", "del", pathname, "--no-color"],
        timeout=300,
        extra_env={"BLOB_READ_WRITE_TOKEN": token},
    )


def _cleanup_expired() -> None:
    response = _post_json("/api/media/jobs/expired", {"worker_id": WORKER_ID})
    for job in response.get("jobs") or []:
        try:
            _delete_private_blob(str(job["blob_pathname"]))
            _post_json("/api/media/jobs/expired/confirm", {"job_id": int(job["id"])}, attempts=3)
            print(f"expired job {job.get('id')} cleaned", flush=True)
        except Exception as exc:
            print(f"expired job {job.get('id')} cleanup failed: {exc}", flush=True)


def _complete(job_token: str, payload: dict[str, Any]) -> None:
    _post_json(f"/api/media/jobs/{job_token}/complete", payload, attempts=5)


def _process(job: dict[str, Any]) -> None:
    token = str(job["job_token"])
    try:
        if not OMNIGET_YTDLP.is_file():
            raise RuntimeError(f"OmniGet engine not found: {OMNIGET_YTDLP}")
        WORK_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="dk-media-", dir=str(WORK_ROOT)) as raw_folder:
            folder = Path(raw_folder)
            output, title = _download(job, folder)
            delivery = _delivery_file(output, str(job["output_format"]))
            blob_pathname = _upload_private_blob(token, delivery)
            _complete(
                token,
                {
                    "ok": True,
                    "source_title": title,
                    "output_name": delivery.name,
                    "output_size_bytes": delivery.stat().st_size,
                    "blob_pathname": blob_pathname,
                },
            )
        print(f"completed job {job.get('id')}", flush=True)
    except Exception as exc:
        message = str(exc).strip() or exc.__class__.__name__
        try:
            _complete(token, {"ok": False, "error": message[:1000]})
        except Exception as report_error:
            print(f"job {job.get('id')} failed and could not report: {report_error}", flush=True)
        print(f"failed job {job.get('id')}: {message}", flush=True)


def main() -> int:
    if not _token():
        print(f"worker token missing: {TOKEN_FILE}", flush=True)
        return 2
    while True:
        try:
            _cleanup_expired()
            response = _post_json("/api/media/jobs/claim", {"worker_id": WORKER_ID})
            job = response.get("job")
            if job:
                _process(job)
            elif ONCE:
                return 0
            else:
                time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            print(f"worker poll failed: {exc}", flush=True)
            if ONCE:
                return 1
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
