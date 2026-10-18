"""Flask SOC Dashboard and Streaming API for TCP Port Reconnaissance."""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request, send_file

import reports
from scanner import SERVICE_PRESETS, TOP_100_PORTS, parse_ports, resolve_target, scan

ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "reports"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
SCAN_LOCK = threading.Lock()

MAX_THREADS = 200
PUBLIC_PORT_CAP = 4096
TARGET_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
ALLOWED_PUBLIC_HOSTS = {"scanme.nmap.org"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")


def _is_trusted_target(target: str, ip: str) -> bool:
    name = target.strip().lower().rstrip(".")
    if name in ALLOWED_PUBLIC_HOSTS or name in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def _validate_target(target: str) -> str:
    host = target.strip()
    if not host or not TARGET_RE.match(host):
        raise ValueError("Invalid target: Enter a valid hostname or IPv4 address.")
    if host.startswith("-"):
        raise ValueError("Target cannot begin with a dash.")
    return host


def _resolve_port_list(preset: str, custom: str, services: list[str]) -> list[int]:
    selected: set[int] = set()
    if preset == "quick":
        selected.update(TOP_100_PORTS)
    elif preset == "standard":
        selected.update(range(1, 1025))
    elif preset == "full":
        selected.update(range(1, 65536))
    elif preset == "custom":
        if custom.strip():
            selected.update(parse_ports(custom))
    else:
        raise ValueError("Unknown scan profile selected.")

    for name in services:
        if name not in SERVICE_PRESETS:
            raise ValueError(f"Unknown service preset group: {name}")
        selected.update(SERVICE_PRESETS[name])

    if not selected:
        raise ValueError("Specify a valid port range or select at least one service preset.")
    return sorted(selected)


def _ports_label(preset: str, custom: str, ports: list[int], services: list[str]) -> str:
    if preset == "quick" and not services:
        return "top-100"
    if preset == "standard" and not services:
        return "1-1024"
    if preset == "full" and not services:
        return "1-65535"
    if len(ports) <= 30:
        return ",".join(str(p) for p in ports)
    return f"{len(ports)} ports"


def equivalent_nmap(target: str, ports_label: str, identify: bool) -> str:
    flags = ["nmap"]
    if identify:
        flags.append("-sV")
    flags.append(f"-p {ports_label}")
    flags.append(target)
    return " ".join(flags)


def _job_public(job: dict) -> dict:
    total = job["total"]
    completed = job["completed"]
    pct = int((completed / total) * 100) if total else 0
    return {
        "id": job["id"],
        "status": job["status"],
        "completed": completed,
        "total": total,
        "percent": pct,
        "elapsed": job.get("elapsed", 0.0),
        "rate": job.get("rate", 0),
        "results": list(job["results"]),
        "logs": list(job.get("logs", [])),
        "error": job.get("error"),
        "target": job["target"],
        "ip": job.get("ip"),
        "settings": job["settings"],
        "equivalent_command": job["equivalent_command"],
        "summary": reports.summary_line(job["results"], job["total"], job.get("elapsed"))
        if job["status"] == "done"
        else None,
        "finished_at": job.get("finished_at"),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    if not data.get("consent"):
        return jsonify({"error": "Consent required: Confirm you are authorized to scan this target."}), 400

    try:
        target = _validate_target(str(data.get("target", "")))
        preset = str(data.get("preset", "standard"))
        custom = str(data.get("ports", ""))
        services = [str(s) for s in data.get("services", [])]
        identify = bool(data.get("identify", True))
        threads = int(data.get("threads", 100))
        ports = _resolve_port_list(preset, custom, services)
        ip = resolve_target(target)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    if threads < 1 or threads > MAX_THREADS:
        return jsonify({"error": f"Thread count must be between 1 and {MAX_THREADS}."}), 400

    trusted = _is_trusted_target(target, ip)
    if preset == "full" and not trusted:
        return jsonify(
            {
                "error": "Full 1–65535 scan is restricted to localhost, private subnets (RFC1918), or scanme.nmap.org."
            }
        ), 400
    if len(ports) > PUBLIC_PORT_CAP and not trusted:
        return jsonify(
            {
                "error": f"Target outside trusted scope is capped at {PUBLIC_PORT_CAP} ports. Choose Quick, Standard, or a scoped range."
            }
        ), 400

    if not SCAN_LOCK.acquire(blocking=False):
        return jsonify({"error": "A scan is already active in this console session. Please wait for completion."}), 409

    ports_label = _ports_label(preset, custom, ports, services)
    job_id = uuid.uuid4().hex[:12]
    now_ts = time.time()
    initial_logs = [
        f"[*] Initializing socket engine with {threads} workers...",
        f"[*] Target resolved: {target} -> {ip}",
        f"[*] Target scope: {'Trusted / Local' if trusted else 'Public Host'}",
        f"[*] Surveying {len(ports)} port(s) [Profile: {preset.upper()}]...",
    ]
    job = {
        "id": job_id,
        "status": "running",
        "completed": 0,
        "total": len(ports),
        "results": [],
        "logs": initial_logs,
        "error": None,
        "target": target,
        "ip": ip,
        "start_time": now_ts,
        "elapsed": 0.0,
        "rate": 0,
        "settings": {
            "preset": preset,
            "ports": ports_label,
            "services": services,
            "identify": identify,
            "threads": threads,
        },
        "equivalent_command": equivalent_nmap(target, ports_label, identify),
        "finished_at": None,
    }
    with JOBS_LOCK:
        JOBS[job_id] = job

    def on_progress(completed: int, total: int, finding: dict | None, port: int | None = None) -> None:
        now = time.time()
        with JOBS_LOCK:
            job["completed"] = completed
            job["total"] = total
            elapsed = max(0.001, now - job["start_time"])
            job["elapsed"] = round(elapsed, 2)
            job["rate"] = int(completed / elapsed) if elapsed > 0 else 0
            if finding:
                job["results"] = sorted(job["results"] + [finding], key=lambda r: r["port"])
                banner_str = f" :: {finding['banner'][:80]}" if finding.get("banner") else ""
                job["logs"].append(
                    f"[+] {finding['port']}/tcp OPEN [{finding.get('service', 'unknown')}]{banner_str}"
                )
            elif port and (completed % max(50, total // 10 or 1) == 0):
                pct = int(completed / total * 100)
                job["logs"].append(f"[*] Progress: {completed}/{total} ports scanned ({pct}%)...")

    def run() -> None:
        try:
            scan(
                target,
                ports,
                threads=threads,
                grab_banner=identify,
                progress_callback=on_progress,
            )
            with JOBS_LOCK:
                elapsed = max(0.001, time.time() - job["start_time"])
                job["status"] = "done"
                job["completed"] = job["total"]
                job["elapsed"] = round(elapsed, 2)
                job["rate"] = int(job["total"] / elapsed) if elapsed > 0 else 0
                job["finished_at"] = _utcnow()
                job["logs"].append(
                    f"[+] Scan completed in {job['elapsed']:.2f}s. Discovered {len(job['results'])} open port(s)."
                )
        except Exception as exc:  # noqa: BLE001
            with JOBS_LOCK:
                elapsed = max(0.001, time.time() - job["start_time"])
                job["status"] = "error"
                job["error"] = str(exc)
                job["elapsed"] = round(elapsed, 2)
                job["finished_at"] = _utcnow()
                job["logs"].append(f"[!] Scan terminated with error: {exc}")
        finally:
            SCAN_LOCK.release()

    threading.Thread(target=run, daemon=True).start()
    return jsonify(_job_public(job))


@app.get("/api/scan/<job_id>")
def api_scan_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            abort(404)
        snapshot = _job_public(job)
    return jsonify(snapshot)


@app.get("/api/progress/<job_id>")
@app.get("/api/scan/<job_id>/events")
def api_progress(job_id: str):
    """Server-Sent Events (SSE) live stream for telemetry and log output."""

    def emit():
        log_cursor = 0
        last_state = None
        while True:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    yield f"data: {json.dumps({'error': 'unknown job'})}\n\n"
                    return
                snapshot = _job_public(job)
                current_logs = job.get("logs", [])
                snapshot["new_logs"] = current_logs[log_cursor:]
                log_cursor = len(current_logs)

            state_tuple = (
                snapshot["status"],
                snapshot["completed"],
                len(snapshot["results"]),
                len(snapshot["new_logs"]),
            )
            if state_tuple != last_state or snapshot["new_logs"]:
                yield f"data: {json.dumps(snapshot)}\n\n"
                last_state = state_tuple

            if snapshot["status"] in {"done", "error"}:
                return
            time.sleep(0.15)

    return Response(
        emit(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/report/<job_id>")
def api_report(job_id: str):
    fmt = (request.args.get("format") or "pdf").lower()
    if fmt not in {"pdf", "csv", "json"}:
        return jsonify({"error": "Format must be pdf, csv, or json"}), 400

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            abort(404)
        if job["status"] != "done":
            return jsonify({"error": "Scan has not concluded yet."}), 409
        payload = {
            "target": job["target"],
            "ip": job.get("ip"),
            "results": list(job["results"]),
            "total": job["total"],
            "elapsed": job.get("elapsed"),
            "settings": job["settings"],
            "equivalent_command": job["equivalent_command"],
            "finished_at": job.get("finished_at"),
        }

    suffix = {"pdf": "pdf", "csv": "csv", "json": "json"}[fmt]
    mime = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json",
    }[fmt]
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", job["target"])[:40]
    filename = f"soc-recon-{safe_host}-{job_id}.{suffix}"
    path = REPORT_DIR / filename
    reports.write_report(path, payload, fmt)
    return send_file(path, mimetype=mime, as_attachment=True, download_name=filename)


if __name__ == "__main__":
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
