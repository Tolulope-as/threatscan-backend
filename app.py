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
import warnings
warnings.filterwarnings('ignore')

from dotenv import load_dotenv
load_dotenv()  # reads the .env file and loads its variables

from feature import FeatureExtraction

# Load model
with open("pickle/model.pkl", "rb") as f:
    model = pickle.load(f)

app = Flask(__name__)

CORS(app, origins=["https://threatscan-sand.vercel.app/"])

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
if not VIRUSTOTAL_API_KEY:
    raise RuntimeError(
        "VIRUSTOTAL_API_KEY environment variable is not set. "
        "Set it before starting the app."
    )

app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

# Free tier: 4 requests/minute. Used to pace sequential calls (e.g. ZIP contents)
MIN_SECONDS_BETWEEN_REQUESTS = 16  # ~3.75 req/min, safely under the 4/min cap


class RateLimiter:
    """Simple pacing helper so we don't blow through the 4 req/min free-tier limit."""
    def __init__(self, min_interval):
        self.min_interval = min_interval
        self.last_call = 0

    def wait(self):
        elapsed = time.time() - self.last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_call = time.time()


rate_limiter = RateLimiter(MIN_SECONDS_BETWEEN_REQUESTS)


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": "File too large. Maximum size is 32MB."}), 413


def _get(url, headers, max_retries=3):
    """GET with 429 backoff."""
    for attempt in range(max_retries):
        rate_limiter.wait()
        resp = requests.get(url, headers=headers)
        if resp.status_code == 429:
            print(f"429 rate limited on GET {url}, backing off...")
            time.sleep(20)
            continue
        return resp
    return resp


def _post(url, headers, **kwargs):
    """POST with 429 backoff (single retry pass is enough for uploads)."""
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
    This is the key fix: EICAR and other known test/malware files almost
    always have an existing report, so this returns a full multi-engine
    verdict instantly, instead of waiting on a fresh analysis that may not
    finish inside the polling window.

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


def poll_analysis(analysis_id, headers, max_attempts=18, wait_seconds=10):
    """
    Poll until VT reports status == 'completed'.

    IMPORTANT: if we run out of attempts and the analysis is still
    queued/in-progress, we return None — NOT the partial data. Partial
    data has near-empty stats and will be misread as "clean" by callers.
    An incomplete analysis must never be silently treated as a safe verdict.
    """
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

        time.sleep(wait_seconds)

    print("Analysis did not complete within polling window — treating as INCOMPLETE, not clean")
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

        data = poll_analysis(analysis_id, headers)
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
      2. Ask VT if it already has a report for this hash (instant, no upload,
         doesn't burn upload quota, and avoids the analysis-timing bug).
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

        print(f"[{filename}] No cached report — uploading for fresh analysis")
        response = _post(
            "https://www.virustotal.com/api/v3/files",
            headers,
            files={"file": (filename, file_bytes)}
        )
        if response.status_code != 200:
            print(f"File upload failed: {response.status_code} {response.text}")
            return None

        analysis_id = response.json()["data"]["id"]
        print(f"[{filename}] Analysis ID: {analysis_id}")

        data = poll_analysis(analysis_id, headers)
        if data is None:
            # Genuinely unfinished — do not report this as safe
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


@app.route("/scan/url", methods=["POST"])
def scan_url():
    try:
        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "URL is required"}), 400

        obj = FeatureExtraction(url)
        features = np.array(obj.getFeaturesList()).reshape(1, 30)
        prediction = model.predict(features)[0]
        proba = model.predict_proba(features)[0]

        ml_verdict = "SAFE" if prediction == 1 else "MALICIOUS"
        ml_confidence = round(float(proba[1]) * 100, 2) if prediction == 1 else round(float(proba[0]) * 100, 2)

        vt_result = scan_url_virustotal(url)
        vt_incomplete = bool(vt_result and vt_result.get("incomplete"))

        if vt_result and not vt_incomplete and vt_result["flagged"]:
            final_verdict = "MALICIOUS"
        elif vt_incomplete:
            # Don't silently fall back to "safe" — be explicit that VT didn't finish
            final_verdict = ml_verdict
        else:
            final_verdict = ml_verdict

        if final_verdict == "SAFE":
            risk_level = "Low"
        elif ml_verdict == "MALICIOUS" and vt_result and not vt_incomplete and vt_result["flagged"]:
            risk_level = "High"
        else:
            risk_level = "Medium"

        engine_result = _empty_engine_result() if (not vt_result or vt_incomplete) else vt_result

        return jsonify({
            "verdict": final_verdict,
            "risk_level": risk_level,
            "vt_status": "incomplete" if vt_incomplete else ("ok" if vt_result else "unavailable"),
            "ml_result": {
                "verdict": ml_verdict,
                "confidence": ml_confidence
            },
            "engine_result": engine_result,
            "threat_category": "Phishing" if final_verdict == "MALICIOUS" else "None",
            "recommendation": (
                "This URL appears safe to visit." if final_verdict == "SAFE"
                else "Do not visit this URL. It has been flagged as a potential threat."
            )
        })

    except Exception as e:
        print(f"Scan URL error: {e}")
        return jsonify({"error": "Failed to scan URL"}), 500


def _scan_zip(file_bytes):
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
        for zip_info in zf.infolist():
            if zip_info.flag_bits & 0x1:
                return jsonify({
                    "verdict": "UNKNOWN",
                    "risk_level": "Medium",
                    "vt_status": "skipped",
                    "ml_result": None,
                    "engine_result": _empty_engine_result(),
                    "threat_category": "Unknown",
                    "recommendation": "This ZIP archive is password-protected and its contents cannot be inspected. Exercise caution before opening it."
                })

        names = [n for n in zf.namelist() if not n.endswith('/')]
        print(f"Files inside ZIP: {names}")

        all_results = []
        any_incomplete = False

        for name in names:
            inner_bytes = zf.read(name)
            inner_result = scan_file_virustotal(inner_bytes, name)
            print(f"Result for {name}: {inner_result}")

            if inner_result is None:
                continue
            if inner_result.get("incomplete"):
                any_incomplete = True
                continue

            all_results.append({"filename": name, "result": inner_result})

        if not all_results and not any_incomplete:
            return jsonify({"error": "Could not scan files inside ZIP"}), 500

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

        return jsonify({
            "verdict": final_verdict,
            "risk_level": risk_level,
            "vt_status": "partial" if any_incomplete else "ok",
            "ml_result": None,
            "engine_result": {
                "malicious_count": total_malicious,
                "suspicious_count": total_suspicious,
                "harmless_count": total_harmless,
                "undetected_count": total_undetected,
                "total_engines": total_engines,
                "flagged": is_flagged,
                "flagged_engines": all_flagged_engines
            },
            "threat_category": "Malware" if final_verdict == "MALICIOUS" else "None",
            "recommendation": recommendation
        })


@app.route("/scan/file", methods=["POST"])
def scan_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        filename = file.filename
        file_bytes = file.read()

        print(f"File received: {filename}, size: {len(file_bytes)} bytes")

        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            try:
                return _scan_zip(file_bytes)
            except zipfile.BadZipFile as e:
                print(f"BadZipFile: {e}")
                # fall through to normal-file handling below
            except Exception as e:
                import traceback
                print(f"ZIP processing error: {e}")
                print(traceback.format_exc())
                return jsonify({"error": f"ZIP processing failed: {str(e)}"}), 500

        print("Processing as normal file")
        vt_result = scan_file_virustotal(file_bytes, filename)

        if vt_result is None:
            return jsonify({"error": "File scan failed"}), 500

        if vt_result.get("incomplete"):
            return jsonify({
                "verdict": "UNKNOWN",
                "risk_level": "Medium",
                "vt_status": "incomplete",
                "ml_result": None,
                "engine_result": _empty_engine_result(),
                "threat_category": "Unknown",
                "recommendation": "Analysis is still in progress on VirusTotal's side. Please try again in a minute."
            })

        final_verdict = "MALICIOUS" if vt_result["flagged"] else "SAFE"

        if final_verdict == "SAFE":
            risk_level = "Low"
        elif vt_result["malicious_count"] > 5:
            risk_level = "High"
        else:
            risk_level = "Medium"

        return jsonify({
            "verdict": final_verdict,
            "risk_level": risk_level,
            "vt_status": "ok",
            "ml_result": None,
            "engine_result": {
                "malicious_count": vt_result["malicious_count"],
                "suspicious_count": vt_result["suspicious_count"],
                "harmless_count": vt_result["harmless_count"],
                "undetected_count": vt_result["undetected_count"],
                "total_engines": vt_result["total_engines"],
                "flagged": vt_result["flagged"],
                "flagged_engines": vt_result["flagged_engines"]
            },
            "threat_category": "Malware" if final_verdict == "MALICIOUS" else "None",
            "recommendation": (
                "This file appears safe." if final_verdict == "SAFE"
                else "Do not open this file. It has been flagged as malicious by multiple security engines."
            )
        })

    except Exception as e:
        import traceback
        print(f"Scan file error: {e}")
        print(traceback.format_exc())
        return jsonify({"error": "Failed to scan file"}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)