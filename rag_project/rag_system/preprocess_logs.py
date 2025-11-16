#!/usr/bin/env python3
# preprocess_logs.py (robuste : gère valeurs non numériques comme "low"/"high")
import json
import glob
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
OUT_DIR = Path("prepared")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "event_summaries.json"

# mapping textual descriptors to numeric values (tunable)
SPEED_MAP = {
    "low": 10.0,
    "medium": 200.0,
    "high": 600.0,
    "very_high": 900.0
}

def load_json_file(p: Path):
    with p.open("r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
            return data if isinstance(data, list) else [data]
        except Exception as e:
            print(f"[WARN] erreur lecture JSON {p.name}: {e}")
            return []

def load_jsonl_file(p: Path):
    records = []
    with p.open("r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                records.append(obj)
            except Exception as e:
                print(f"[WARN] erreur parsing JSONL {p.name} line {i}: {e}")
    return records

def load_all_records(data_dir: Path):
    records = []
    for p in sorted(data_dir.glob("*")):
        if p.suffix.lower() == ".json":
            recs = load_json_file(p)
            print(f"Loaded {len(recs)} from {p.name}")
            records.extend(recs)
        elif p.suffix.lower() == ".jsonl":
            recs = load_jsonl_file(p)
            print(f"Loaded {len(recs)} from {p.name}")
            records.extend(recs)
    return records

def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return default

def safe_float(value, default=0.0):
    # accepts numeric strings, and known descriptors like 'low'
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        val = value.strip().lower()
        # try direct numeric parse
        try:
            return float(val)
        except Exception:
            # map textual categories
            if val in SPEED_MAP:
                return float(SPEED_MAP[val])
            # try to extract digits if present
            digits = ''.join(ch for ch in val if (ch.isdigit() or ch == '.' or ch == '-'))
            if digits:
                try:
                    return float(digits)
                except Exception:
                    return default
            return default
    # fallback
    return default

def safe_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y", "t"):
            return True
        if v in ("false", "0", "no", "n", "f"):
            return False
    return default

def ensure_extra_features(r, record_id=None):
    # Normalise extra_features into expected schema with safe conversions
    ef = r.get("extra_features", {})
    if not isinstance(ef, dict):
        ef = {}

    fail_count = safe_int(ef.get("fail_count_5min", ef.get("fail_count", 0)), default=0)
    distinct_ips = safe_int(ef.get("distinct_ips", ef.get("distinct_ip_count", 1)), default=1)
    geo_velocity = safe_float(ef.get("geo_velocity", ef.get("velocity", 0.0)), default=0.0)
    device_change = safe_bool(ef.get("device_change", False))
    success_count = safe_int(ef.get("success_count", 1 if r.get("outcome") == "success" else 0), default=(1 if r.get("outcome") == "success" else 0))

    # If any original values were non-numeric, log a short warning for traceability
    # (but continue processing)
    # Example: if original provided 'low' for geo_velocity, we map it but inform dev
    orig_geo = ef.get("geo_velocity") if "geo_velocity" in ef else ef.get("velocity")
    if orig_geo is not None:
        try:
            float(orig_geo)
        except Exception:
            print(f"[WARN] record id={record_id}: geo_velocity non-numeric '{orig_geo}' -> mapped to {geo_velocity}")

    return {
        "fail_count_5min": fail_count,
        "distinct_ips": distinct_ips,
        "geo_velocity": geo_velocity,
        "device_change": device_change,
        "success_count": success_count
    }

def ensure_recent_events(r):
    revents = r.get("recent_events")
    if isinstance(revents, list) and len(revents) > 0:
        normalized = []
        for ev in revents:
            try:
                evc = dict(ev)
                # ensure timestamp string exists
                ts = evc.get("timestamp")
                if ts is None:
                    evc["timestamp"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
                normalized.append(evc)
            except Exception:
                continue
        if normalized:
            return normalized
    # Otherwise create a minimal recent_events from the base row
    ts = r.get("timestamp")
    if not ts:
        ts = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    return [{
        "timestamp": ts,
        "outcome": r.get("outcome"),
        "ip": r.get("ip"),
        "device": r.get("device_info")
    }]

def to_event_summary(r):
    sid = r.get("id")
    try:
        summary = {
            "id": sid,
            "user_id": r.get("user_id"),
            "recent_events": ensure_recent_events(r),
            "features": ensure_extra_features(r, record_id=sid),
            "label": r.get("label", "unknown")
        }
        return summary
    except Exception as e:
        print(f"[WARN] erreur transformation record id={sid}: {e}")
        return None

def main():
    records = load_all_records(DATA_DIR)
    if not records:
        print("[ERROR] Aucun fichier JSON/JSONL trouvé dans", DATA_DIR)
        return
    print(f"Total records loaded: {len(records)}")
    summaries = []
    for r in records:
        s = to_event_summary(r)
        if s:
            summaries.append(s)
    # write outputs
    with OUT_FILE.open("w", encoding="utf-8") as fh:
        json.dump(summaries, fh, ensure_ascii=False, indent=2)
    print(f"Saved {len(summaries)} event_summaries -> {OUT_FILE}")

if __name__ == "__main__":
    main()
