from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pickle
import requests
import os
import zipfile
import io
import time
import hashlib
import uuid
import threading
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor
warnings.filterwarnings('ignore')

from dotenv import load_dotenv
load_dotenv()  # reads the .env file and loads its variables

from feature import FeatureExtraction

# Load model
with open("pickle/model.pkl", "rb") as f:
    model = pickle.load(f)

app = Flask(__name__)

CORS(app, origins=[
    "https://threatscan-sand.vercel.app",
    "https://threatscan-project.vercel.app",
])

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
if not VIRUSTOTAL_API_KEY:
    raise RuntimeError(
        "VIRUSTOTAL_API_KEY environment variable is not set. "
        "Set it before starting the app."
    )

app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
# VirusTotal free tier: 4 requests/minute. 16s spacing = ~3.75 req/min.
MIN_SECONDS_BETWEEN_REQUESTS = 16
POLL_MAX_ATTEMPTS = 12          # fallback polls (16s apart) if the first read is not ready
FILE_INITIAL_WAIT = 30          # pause after uploading a file, before the first result read
URL_INITIAL_WAIT = 15           # URL analyses usually finish sooner
HTTP_TIMEOUT = 30               # seconds, normal VirusTotal calls
UPLOAD_TIMEOUT = 120            # seconds, file uploads

# Office/OpenDocument files are ZIP containers internally. Unpacking them only
# yields generic XML parts and hides macros, so they are scanned as ONE file.
OFFICE_EXTS = {
    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp", ".jar", ".apk"
}
# When scanning a real archive, look at these inner file types first.
RISKY_EXTS = {
    ".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd",
    ".msi", ".jar", ".docm", ".xlsm", ".pptm", ".lnk", ".hta"
}
MAX_INNER_FILES = 5                          # inner files scanned per archive
MAX_UNZIPPED_BYTES = 64 * 1024 * 1024        # zip-bomb protection
JOB_TTL_SECONDS = 60 * 60                    # keep finished results for 1 hour


class ScanError(Exception):
    """An error whose message is safe to show to the user."""


# ---------------------------------------------------------------------------
# Thread-safe rate limiter (shared by all scan jobs)
# ---------------------------------------------------------------------------
class RateLimiter:
    """Reserves time slots so VirusTotal calls are spaced out, even across threads."""
    def __init__(self, min_interval):
        self.min_interval = min_interval
        self.next_slot = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.time()
            start = max(now, self.next_slot)
            self.next_slot = start + self.min_interval
        delay = start - now
        if delay > 0:
            time.sleep(delay)


rate_limiter = RateLimiter(MIN_SECONDS_BETWEEN_REQUESTS)


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": "File too large. Maximum size is 32MB."}), 413


# ---------------------------------------------------------------------------
# Background job store
# ---------------------------------------------------------------------------
# NOTE: jobs live in memory, so run gunicorn with exactly ONE worker process
# (use --threads for concurrency). See the start command in the instructions.
jobs = {}
jobs_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=3)


def _cleanup_jobs():
    cutoff = time.time() - JOB_TTL_SECONDS
    with jobs_lock:
        for job_id in [j for j, v in jobs.items() if v["created"] < cutoff]:
            del jobs[job_id]


def submit_job(fn, *args):
    _cleanup_jobs()
    job_id = uuid.uuid4().hex
    with jobs_lock:
        jobs[job_id] = {
            "status": "processing",
            "created": time.time(),
            "result": None,
            "error": None,
        }

    def runner():
        try:
            result = fn(*args)
            with jobs_lock:
                jobs[job_id].update(status="done", result=result)
        except ScanError as e:
            with jobs_lock:
                jobs[job_id].update(status="error", error=str(e))
        except Exception as e:
            print(f"Job {job_id} crashed: {e}")
            print(traceback.format_exc())
            with jobs_lock:
                jobs[job_id].update(
                    status="error",
                    error="Scan failed. Please try again."
                )

    executor.submit(runner)
    return job_id


# ---------------------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------------------
def _get(url, headers, max_retries=3):
    """GET with pacing, timeout and 429 backoff."""
    resp = None
    for attempt in range(max_retries):
        rate_limiter.wait()
        resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code == 429:
            print(f"429 rate limited on GET {url}, backing off...")
            time.sleep(20)
            continue
        return resp
    return resp


def _post(url, headers, **kwargs):
    """POST with pacing, timeout and 429 backoff."""
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    resp = None
    for attempt in range(3):
        rate_limiter.wait()
        resp = requests.post(url, headers=headers, **kwargs)
        if resp.status_code == 429:
            print(f"429 rate limited on POST {url}, backing off...")
            time.sleep(20)
            continue
        return resp
    return resp


def get_cached_report(file_hash, headers):
    """
    Check whether VirusTotal already has a report for this exact file hash.
    Returns (stats, results) or (None, None) if not found.
    """
    try:
        resp = _get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers)
        if resp.status_code == 200:
            attrs = resp.json()["data"]["attributes"]
            return attrs.get("last_analysis_stats"), attrs.get("last_analysis_results", {})
        elif resp.status_code == 404:
            return None, None
        else:
            print(f"Hash lookup failed: {resp.status_code} {resp.text}")
            return None, None
    except Exception as e:
        print(f"Hash lookup error: {e}")
        return None, None


def poll_analysis(analysis_id, headers, max_attempts=POLL_MAX_ATTEMPTS, initial_wait=0):
    """
    Wait `initial_wait` seconds, then read the result. In most cases the analysis
    is already finished, so this costs a single request. If it is not ready, keep
    polling (paced by the rate limiter) up to max_attempts.
    If the analysis never completes we return None, NOT partial data, so an
    unfinished analysis is never misread as "clean".
    """
    if initial_wait:
        print(f"Waiting {initial_wait}s before reading the result...")
        time.sleep(initial_wait)

    for attempt in range(max_attempts):
        result = _get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers)

        if result.status_code != 200:
            print(f"Poll failed: {result.status_code} {result.text}")
            return None

        data = result.json()["data"]["attributes"]
        status = data.get("status")
        print(f"Attempt {attempt + 1}/{max_attempts}: status = {status}")

        if status == "completed":
            return data

    print("Analysis did not complete within polling window - treating as INCOMPLETE, not clean")
    return None


def _build_verdict_from_stats(stats, results):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    flagged_engines = []
    for engine_name, engine_data in (results or {}).items():
        category = engine_data.get("category", "")
        threat = engine_data.get("result", "")
        if category in ["malicious", "suspicious"] and threat:
            flagged_engines.append({
                "engine": engine_name,
                "category": category,
                "threat": threat
            })
    flagged_engines = flagged_engines[:10]

    return {
        "incomplete": False,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": harmless,
        "undetected_count": undetected,
        "total_engines": total,
        "flagged": malicious > 0 or suspicious > 0,
        "flagged_engines": flagged_engines
    }


def scan_url_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        response = _post(
            "https://www.virustotal.com/api/v3/urls",
            headers,
            data={"url": url}
        )
        if response.status_code != 200:
            print(f"URL submission failed: {response.status_code} {response.text}")
            return None

        analysis_id = response.json()["data"]["id"]
        print(f"URL Analysis ID: {analysis_id}")

        data = poll_analysis(analysis_id, headers, initial_wait=URL_INITIAL_WAIT)
        if data is None:
            return {"incomplete": True}

        return _build_verdict_from_stats(data.get("stats", {}), data.get("results", {}))
    except Exception as e:
        print(f"VirusTotal URL error: {e}")
        return None


def scan_file_virustotal(file_bytes, filename):
    """
    Hash-check-first strategy:
      1. Compute SHA-256 locally.
      2. Ask VT if it already has a report for this hash (no upload needed).
      3. Only if VT has never seen this exact file do we upload it and poll.
    """
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        print(f"[{filename}] SHA-256: {file_hash}")

        cached_stats, cached_results = get_cached_report(file_hash, headers)

        if cached_stats is not None:
            print(f"[{filename}] Using cached VirusTotal report (hash match)")
            return _build_verdict_from_stats(cached_stats, cached_results)

        print(f"[{filename}] No cached report - uploading for fresh analysis")
        response = _post(
            "https://www.virustotal.com/api/v3/files",
            headers,
            files={"file": (filename, file_bytes)},
            timeout=UPLOAD_TIMEOUT
        )
        if response.status_code != 200:
            print(f"File upload failed: {response.status_code} {response.text}")
            return None

        analysis_id = response.json()["data"]["id"]
        print(f"[{filename}] Analysis ID: {analysis_id}")

        data = poll_analysis(analysis_id, headers, initial_wait=FILE_INITIAL_WAIT)
        if data is None:
            return {"incomplete": True}

        return _build_verdict_from_stats(data.get("stats", {}), data.get("results", {}))
    except Exception as e:
        print(f"VirusTotal file error: {e}")
        return None


def _empty_engine_result():
    return {
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "undetected_count": 0,
        "total_engines": 0,
        "flagged": False,
        "flagged_engines": []
    }


def _report(verdict, risk_level, vt_status, engine_result, category,
            recommendation, ml_result=None):
    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "vt_status": vt_status,
        "ml_result": ml_result,
        "engine_result": engine_result,
        "threat_category": category,
        "recommendation": recommendation
    }


# ---------------------------------------------------------------------------
# Scan logic (runs in a background thread, returns a plain dict)
# ---------------------------------------------------------------------------
def process_url(url):
    obj = FeatureExtraction(url)
    features = np.array(obj.getFeaturesList()).reshape(1, 30)
    prediction = model.predict(features)[0]
    proba = model.predict_proba(features)[0]

    ml_verdict = "SAFE" if prediction == 1 else "MALICIOUS"
    ml_confidence = round(float(proba[1]) * 100, 2) if prediction == 1 else round(float(proba[0]) * 100, 2)

    vt_result = scan_url_virustotal(url)
    vt_incomplete = bool(vt_result and vt_result.get("incomplete"))
    vt_flagged = bool(vt_result and not vt_incomplete and vt_result["flagged"])

    final_verdict = "MALICIOUS" if vt_flagged else ml_verdict

    if final_verdict == "SAFE":
        risk_level = "Low"
    elif ml_verdict == "MALICIOUS" and vt_flagged:
        risk_level = "High"
    else:
        risk_level = "Medium"

    engine_result = _empty_engine_result() if (not vt_result or vt_incomplete) else vt_result
    vt_status = "incomplete" if vt_incomplete else ("ok" if vt_result else "unavailable")

    return _report(
        final_verdict, risk_level, vt_status, engine_result,
        "Phishing" if final_verdict == "MALICIOUS" else "None",
        ("This URL appears safe to visit." if final_verdict == "SAFE"
         else "Do not visit this URL. It has been flagged as a potential threat."),
        ml_result={"verdict": ml_verdict, "confidence": ml_confidence}
    )


def process_zip(filename, file_bytes):
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
        infos = [i for i in zf.infolist() if not i.filename.endswith("/")]

        if any(i.flag_bits & 0x1 for i in infos):
            return _report(
                "UNKNOWN", "Medium", "skipped", _empty_engine_result(), "Unknown",
                "This ZIP archive is password-protected and its contents cannot be "
                "inspected. Exercise caution before opening it."
            )

        if sum(i.file_size for i in infos) > MAX_UNZIPPED_BYTES:
            raise ScanError("This archive is too large once extracted to be scanned safely.")

        # Risky file types first, then the rest; cap how many we scan.
        infos.sort(key=lambda i: (os.path.splitext(i.filename)[1].lower() not in RISKY_EXTS,
                                  i.filename))
        selected = infos[:MAX_INNER_FILES]
        skipped = len(infos) - len(selected)
        print(f"Archive has {len(infos)} files, scanning archive + {len(selected)} inner files")

        # First scan the archive itself, then the selected inner files.
        scan_list = [(filename or "archive.zip", None)] + [(i.filename, i) for i in selected]

        all_results = []
        any_incomplete = False

        for name, info in scan_list:
            data = file_bytes if info is None else zf.read(info)
            inner_result = scan_file_virustotal(data, name)
            print(f"Result for {name}: {inner_result}")

            if inner_result is None:
                continue
            if inner_result.get("incomplete"):
                any_incomplete = True
                continue

            all_results.append({"filename": name, "result": inner_result})

    if not all_results and not any_incomplete:
        raise ScanError("Could not scan the files inside this ZIP. Please try again.")

    total_malicious = sum(r["result"]["malicious_count"] for r in all_results)
    total_suspicious = sum(r["result"]["suspicious_count"] for r in all_results)
    total_harmless = sum(r["result"]["harmless_count"] for r in all_results)
    total_undetected = sum(r["result"]["undetected_count"] for r in all_results)
    total_engines = max((r["result"]["total_engines"] for r in all_results), default=0)
    is_flagged = any(r["result"]["flagged"] for r in all_results)

    all_flagged_engines = []
    for r in all_results:
        for engine in r["result"]["flagged_engines"]:
            engine = dict(engine)
            engine["filename"] = r["filename"]
            all_flagged_engines.append(engine)
    all_flagged_engines = all_flagged_engines[:10]

    if is_flagged:
        final_verdict = "MALICIOUS"
    elif any_incomplete:
        final_verdict = "UNKNOWN"
    else:
        final_verdict = "SAFE"

    if final_verdict == "MALICIOUS":
        risk_level = "High" if total_malicious > 5 else "Medium"
    elif final_verdict == "UNKNOWN":
        risk_level = "Medium"
    else:
        risk_level = "Low"

    recommendation = {
        "MALICIOUS": "Do not open this ZIP archive. One or more files inside have been flagged as malicious.",
        "UNKNOWN": "Some files inside this ZIP could not be fully analyzed yet. Re-check shortly before opening.",
        "SAFE": "This ZIP archive appears safe."
    }[final_verdict]
    if skipped > 0:
        recommendation += (f" Note: only the archive and {len(selected)} of its {len(infos)} "
                           f"files were scanned.")

    return _report(
        final_verdict, risk_level, "partial" if any_incomplete else "ok",
        {
            "malicious_count": total_malicious,
            "suspicious_count": total_suspicious,
            "harmless_count": total_harmless,
            "undetected_count": total_undetected,
            "total_engines": total_engines,
            "flagged": is_flagged,
            "flagged_engines": all_flagged_engines
        },
        "Malware" if final_verdict == "MALICIOUS" else "None",
        recommendation
    )


def process_file(filename, file_bytes):
    ext = os.path.splitext(filename or "")[1].lower()

    # Real archives are unpacked; Office documents (also ZIPs) are scanned whole.
    if ext not in OFFICE_EXTS and zipfile.is_zipfile(io.BytesIO(file_bytes)):
        try:
            return process_zip(filename, file_bytes)
        except zipfile.BadZipFile as e:
            print(f"BadZipFile: {e} - scanning as a normal file")

    print("Processing as normal file")
    vt_result = scan_file_virustotal(file_bytes, filename or "upload")

    if vt_result is None:
        raise ScanError("File scan failed. VirusTotal could not be reached. Please try again.")

    if vt_result.get("incomplete"):
        return _report(
            "UNKNOWN", "Medium", "incomplete", _empty_engine_result(), "Unknown",
            "Analysis is still in progress on VirusTotal's side. Please try again in a minute."
        )

    final_verdict = "MALICIOUS" if vt_result["flagged"] else "SAFE"

    if final_verdict == "SAFE":
        risk_level = "Low"
    elif vt_result["malicious_count"] > 5:
        risk_level = "High"
    else:
        risk_level = "Medium"

    return _report(
        final_verdict, risk_level, "ok",
        {
            "malicious_count": vt_result["malicious_count"],
            "suspicious_count": vt_result["suspicious_count"],
            "harmless_count": vt_result["harmless_count"],
            "undetected_count": vt_result["undetected_count"],
            "total_engines": vt_result["total_engines"],
            "flagged": vt_result["flagged"],
            "flagged_engines": vt_result["flagged_engines"]
        },
        "Malware" if final_verdict == "MALICIOUS" else "None",
        ("This file appears safe." if final_verdict == "SAFE"
         else "Do not open this file. It has been flagged as malicious by multiple security engines.")
    )


# ---------------------------------------------------------------------------
# Routes: start a scan -> get a scan_id -> poll /scan/status/<scan_id>
# ---------------------------------------------------------------------------
@app.route("/scan/url", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    job_id = submit_job(process_url, url)
    return jsonify({"scan_id": job_id, "status": "processing"}), 202


@app.route("/scan/file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    filename = file.filename
    file_bytes = file.read()
    print(f"File received: {filename}, size: {len(file_bytes)} bytes")

    job_id = submit_job(process_file, filename, file_bytes)
    return jsonify({"scan_id": job_id, "status": "processing"}), 202


@app.route("/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        snapshot = dict(job) if job else None

    if snapshot is None:
        return jsonify({"status": "not_found",
                        "error": "Scan not found. It may have expired or the server restarted."}), 404

    if snapshot["status"] == "done":
        return jsonify({"status": "done", "result": snapshot["result"]})
    if snapshot["status"] == "error":
        return jsonify({"status": "error", "error": snapshot["error"]})
    return jsonify({"status": "processing"})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False)