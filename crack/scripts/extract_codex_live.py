#!/usr/bin/env python3
"""Structurally-redacting extractor for a LIVE Codex CLI/Desktop session capture.

extract_live.py consumes a whistle *export* (a flat JSON array of sessions) and
knows Claude's body shapes. This script consumes the raw response of whistle's
`GET /cgi-bin/get-data?ids=<...>` API instead — an object whose sessions hang off
`obj["data"]["data"]`, keyed by whistle id — and knows Codex's shapes: the
`/backend-api/codex/models` catalog (whose per-model `model_messages` prompt
templates are elided, since they are prose, not fingerprint), the WebSocket
handshakes to `/backend-api/codex/responses`, and the analytics / wham / ps
sidecar traffic.

Header NAMES, their case, and their wire ORDER are preserved verbatim from
`req.rawHeaderNames` — that ordering IS the fingerprint. Only identity VALUES are
masked, each distinct value getting a stable `<PLACEHOLDER>` so cross-row
equalities (x-client-request-id == session-id == thread-id) survive redaction.

Usage:
    python3 crack/scripts/extract_codex_live.py /path/to/whistle-get-data.json [outdir]

Default outdir = crack/codexv0.153.4/rows/. The source dump is NOT copied or
committed.
"""
import base64
import gzip
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CRACK_ROOT = os.path.dirname(HERE)

# Headers whose value is a secret or a per-request correlator. Masked wholesale.
MASK_HEADERS = {
    "authorization": "Bearer <JWT_REDACTED>",
    "cookie": "<COOKIES_REDACTED>",
    "set-cookie": "<REDACTED>",
    "sec-websocket-key": "<WS_KEY>",
    "sec-websocket-accept": "<WS_ACCEPT>",
    "cf-ray": "<REDACTED>",
    "etag": "<REDACTED>",
    "x-oai-request-id": "<REDACTED>",
    "x-request-id": "<REDACTED>",
    "report-to": "<CF_REPORT_TO_REDACTED>",
    "x-models-etag": "<MODELS_ETAG>",
}

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
# ChatGPT ids that are not UUIDs: user-XXXX, org-XXXX, authsess_XXXX, app_XXXX.
OPAQUE_ID_RE = re.compile(r"\b(?:user|org)-[A-Za-z0-9_]{8,}|\bauthsess_[A-Za-z0-9]{8,}")


class Redactor:
    """Assigns each distinct identity value a stable placeholder.

    Stability is the point: the handshake's equality
    x-client-request-id == session-id == thread-id is a fingerprint fact, and it
    only survives redaction if the same UUID maps to the same placeholder
    everywhere it appears.
    """

    def __init__(self, known=None):
        self.map = dict(known or {})
        self.counters = {}

    def placeholder(self, kind):
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        return "<%s>" % kind if n == 1 else "<%s_%d>" % (kind, n)

    def sub_uuid(self, value):
        if value not in self.map:
            self.map[value] = self.placeholder("UUID")
        return self.map[value]

    def scrub(self, text):
        if not isinstance(text, str):
            return text
        text = JWT_RE.sub("<JWT_REDACTED>", text)
        text = EMAIL_RE.sub("<EMAIL>", text)
        text = OPAQUE_ID_RE.sub("<OPAQUE_ID>", text)
        return UUID_RE.sub(lambda m: self.sub_uuid(m.group(0)), text)

    def walk(self, node):
        if isinstance(node, dict):
            return {k: self.walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self.walk(v) for v in node]
        return self.scrub(node)


def body_text(section):
    """Decode a whistle body section to text. Bodies live in .base64 when binary
    or when whistle could not inline them; .body is the already-decoded form."""
    raw = section.get("base64")
    if raw:
        try:
            data = base64.b64decode(raw)
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            return data.decode("utf-8", "replace")
        except Exception:
            pass
    body = section.get("body")
    if isinstance(body, str):
        return body
    if body:
        return json.dumps(body, ensure_ascii=False)
    return None


def maybe_json(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return text


def elide_prose(node, limit=160):
    """Replace every long free-text string with a head + a character count.

    Applied to the model catalog's `model_messages` / `base_instructions` (prose
    instruction templates, tens of KB per model) and to the plugin store's
    tools/list result (third-party tool schemas). Neither is fingerprint; both
    would otherwise make the archive an order of magnitude larger than the
    signal in it. Capability FLAGS are untouched — only strings past `limit`."""
    if isinstance(node, dict):
        return {k: elide_prose(v, limit) for k, v in node.items()}
    if isinstance(node, list):
        return [elide_prose(v, limit) for v in node]
    if isinstance(node, str) and len(node) > limit:
        return node[:limit] + "… <elided, %d chars total>" % len(node)
    return node


def elide_catalog_prose(catalog, limit=160):
    if not isinstance(catalog, dict):
        return catalog
    for model in catalog.get("models", []):
        if not isinstance(model, dict):
            continue
        for key in ("model_messages", "base_instructions"):
            if key in model:
                model[key] = elide_prose(model[key], limit)
    return catalog


def redact_headers(headers, order, red):
    out = {}
    lowered = {k.lower(): k for k in headers}
    for name in order or list(headers):
        key = lowered.get(name.lower(), name)
        if key not in headers:
            continue
        value = headers[key]
        mask = MASK_HEADERS.get(name.lower())
        out[name] = mask if mask else red.scrub(value)
    for key, value in headers.items():
        if key in out or any(k.lower() == key.lower() for k in out):
            continue
        mask = MASK_HEADERS.get(key.lower())
        out[key] = mask if mask else red.scrub(value)
    return out


def header_order(section):
    names = section.get("rawHeaderNames")
    if isinstance(names, dict):
        # whistle maps lowercase -> on-the-wire spelling, insertion-ordered.
        return list(names.values())
    if isinstance(names, list):
        return names
    return list(section.get("headers", {}))


def emit(session, note, red, elide_catalog=False, elide_all=False):
    req = session.get("req", {}) or {}
    res = session.get("res", {}) or {}
    req_order = header_order(req)
    res_order = header_order(res)

    req_body = maybe_json(body_text(req))
    res_body = maybe_json(body_text(res))
    if elide_catalog:
        res_body = elide_catalog_prose(res_body)
    if elide_all:
        res_body = elide_prose(res_body)

    return {
        "_note": note,
        "method": req.get("method", "GET"),
        "url": red.scrub(session.get("url", "")),
        "httpVersion": req.get("httpVersion", "1.1"),
        "req_headers": redact_headers(req.get("headers", {}), req_order, red),
        "req_header_order": [n for n in req_order],
        "req_body": red.walk(req_body),
        "status": res.get("statusCode"),
        "res_headers": redact_headers(res.get("headers", {}), res_order, red),
        "res_body": red.walk(res_body),
    }


# (filename, url substring, method or None, note). First match wins; a rule may
# fire more than once only if its filename carries a {n} slot.
RULES = [
    ("01-get-codex-models.json", "/backend-api/codex/models", "GET",
     "GET /backend-api/codex/models?client_version=0.153.4 (200). The 9-model "
     "catalog a Pro account sees. Every capability flag is verbatim; the prose "
     "instruction templates under model_messages are elided. gpt-6-astra is new "
     "at this version (minimal_client_version 0.153.0) and leads the list at "
     "priority 1; gpt-reserve is present but visibility \"hide\"."),
    ("10-ws-handshake-codex-responses-{n}.json", "/backend-api/codex/responses", None,
     "codex-tui/0.153.4 WebSocket handshake. Header names/case/order verbatim "
     "from req.rawHeaderNames; only identity values are masked. NOTE vs "
     "codexapp0.147.0: x-codex-routing-hint IS present on the upgrade at this "
     "version, sitting between x-codex-turn-metadata and "
     "sec-websocket-extensions, and x-codex-turn-metadata carries seven more "
     "fields. Subagent connections additionally carry x-codex-parent-thread-id "
     "and x-openai-subagent."),
    ("20-post-analytics-events-{n}.json", "/codex/analytics-events/events", "POST",
     "POST /backend-api/codex/analytics-events/events — the CLI's own telemetry "
     "batch. Kept for the header set and the event envelope shape."),
    ("30-get-wham-usage.json", "/backend-api/wham/usage", "GET",
     "GET /backend-api/wham/usage — the quota probe cc-core's auth/codex_usage.go parses."),
    ("31-get-wham-rate-limit-reset-credits.json", "/wham/rate-limit-reset-credits", "GET",
     "GET /backend-api/wham/rate-limit-reset-credits — credit reset schedule."),
    ("32-get-wham-settings-user.json", "/backend-api/wham/settings/user", "GET",
     "GET /backend-api/wham/settings/user — per-user Codex settings."),
    ("40-post-ps-mcp-{n}.json", "/backend-api/ps/mcp", "POST",
     "POST /backend-api/ps/mcp — the plugin-store MCP channel the CLI opens at "
     "start (initialize, notifications/initialized, tools/list). The tools/list "
     "result is third-party plugin schemas, not fingerprint, so its long strings "
     "are elided."),
    ("41-get-ps-plugins-installed.json", "/ps/plugins/installed", "GET",
     "GET /backend-api/ps/plugins/installed — plugin-store sidecar."),
    ("42-get-ps-plugins-list.json", "/ps/plugins/list", "GET",
     "GET /backend-api/ps/plugins/list — plugin-store sidecar (paged; the CLI "
     "long-polls this for the whole session)."),
    ("43-get-plugins-featured.json", "/plugins/featured", "GET",
     "GET /backend-api/plugins/featured?platform=codex — plugin-store sidecar."),
    ("44-post-ps-apps-batch.json", "/backend-api/ps/apps/batch", "POST",
     "POST /backend-api/ps/apps/batch — plugin-store sidecar."),
    ("50-post-otlp-v1-metrics.json", "/otlp/v1/metrics", "POST",
     "POST https://ab.chatgpt.com/otlp/v1/metrics — OTLP metrics sidecar."),
]


def _rewrite(path, row):
    with open(path, "w") as fh:
        json.dump(row, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def postprocess(outdir):
    """Name the multi-instance rows by what distinguishes them, drop duplicates,
    and emit the decoded turn-metadata companion row.

    The RULES table can only match on URL, so handshakes and analytics batches
    all land under a numbered pattern. What actually distinguishes them lives in
    the payload: which subagent a handshake is for, which event_type a batch
    carries, which JSON-RPC method an mcp POST invokes."""
    import glob

    def load(name):
        with open(os.path.join(outdir, name)) as fh:
            return json.load(fh)

    # --- handshakes: role comes from x-openai-subagent + metadata.thread_source
    for path in sorted(glob.glob(os.path.join(outdir, "10-ws-handshake-codex-responses-*.json"))):
        row = json.load(open(path))
        headers = row["req_headers"]
        meta = json.loads(headers["x-codex-turn-metadata"])
        if headers.get("x-openai-subagent"):
            name = "12-ws-handshake-subagent-%s.json" % headers["x-openai-subagent"]
            row["_note"] = (
                "codex-tui/%s WebSocket handshake for a SUBAGENT connection (%s). Two headers "
                "appear here that a plain thread does not send — x-codex-parent-thread-id and "
                "x-openai-subagent — between x-codex-turn-metadata and x-codex-routing-hint, and "
                "the metadata gains parent_thread_id/subagent_kind after request_kind."
                % (headers.get("version"), headers["x-openai-subagent"]))
        elif meta.get("thread_source") == "user":
            name = "10-ws-handshake-codex-responses.json"
            row["_note"] = (
                "codex-tui/%s WebSocket handshake, ordinary user thread. Header names/case/order "
                "verbatim from req.rawHeaderNames; only identity values are masked. Two deltas vs "
                "codexapp0.147.0: (1) x-codex-routing-hint IS present on the upgrade, between "
                "x-codex-turn-metadata and sec-websocket-extensions — cc-core/codexws/headers.go "
                "omits it on the strength of the 0.135.0/0.147.0 captures, and that reasoning is "
                "superseded by this row; (2) x-codex-turn-metadata carries seven more fields. "
                "x-client-request-id == session-id == thread-id still holds on a fresh thread."
                % headers.get("version"))
        else:
            name = "11-ws-handshake-%s-thread.json" % meta.get("thread_source", "other")
            row["_note"] = (
                "codex-tui/%s WebSocket handshake for a %s-initiated thread (sandbox_mode %r, "
                "auto_review_enabled %r), routed at %r. Evidence that thread_source, sandbox_mode "
                "and auto_review_enabled genuinely vary per connection."
                % (headers.get("version"), meta.get("thread_source"), meta.get("sandbox_mode"),
                   meta.get("auto_review_enabled"), headers.get("x-codex-routing-hint")))
        os.remove(path)
        _rewrite(os.path.join(outdir, name), row)

    # --- analytics: one representative row per distinct event_type tuple
    seen = {}
    for path in sorted(glob.glob(os.path.join(outdir, "20-post-analytics-events-*.json"))):
        row = json.load(open(path))
        events = (row.get("req_body") or {}).get("events") or []
        kinds = tuple(e.get("event_type") for e in events)
        os.remove(path)
        if kinds in seen:
            continue
        seen[kinds] = True
        slug = "-".join(sorted({(k or "unknown").replace("codex_", "").replace("_event", "")
                                for k in kinds}))
        _rewrite(os.path.join(outdir, "2%d-post-analytics-events-%s.json" % (len(seen), slug)), row)

    # --- ps/mcp: one row per JSON-RPC method
    seen = set()
    for path in sorted(glob.glob(os.path.join(outdir, "40-post-ps-mcp-*.json"))):
        row = json.load(open(path))
        method = (row.get("req_body") or {}).get("method") or "unknown"
        os.remove(path)
        if method in seen:
            continue
        seen.add(method)
        _rewrite(os.path.join(outdir, "40-post-ps-mcp-%s.json" % method.replace("/", "-")), row)

    # --- ps/mcp tools/list: keep the envelope, sample the tool array.
    # 200-odd third-party plugin tool schemas are structural bulk, not
    # fingerprint; three of them are enough to show the shape.
    tools_path = os.path.join(outdir, "40-post-ps-mcp-tools-list.json")
    if os.path.exists(tools_path):
        row = json.load(open(tools_path))
        result = (row.get("res_body") or {}).get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            total = len(result["tools"])
            result["tools"] = result["tools"][:3]
            result["_tools_elided"] = "%d of %d tool schemas dropped" % (total - 3, total)
            row["_note"] += (" The tools array is sampled to the first 3 of %d entries — the "
                             "remainder is third-party plugin schemas, not fingerprint." % total)
            _rewrite(tools_path, row)

    # --- decoded turn-metadata companion, matching the codexapp0.147.0 convention
    variants = {}
    for path in sorted(glob.glob(os.path.join(outdir, "1?-ws-handshake-*.json"))):
        row = json.load(open(path))
        headers = row["req_headers"]
        meta = json.loads(headers["x-codex-turn-metadata"])
        label = headers.get("x-openai-subagent") or meta.get("thread_source") or "thread"
        variants[label] = {
            "source_row": os.path.basename(path),
            "x-codex-routing-hint": headers.get("x-codex-routing-hint"),
            "x-openai-subagent": headers.get("x-openai-subagent"),
            "decoded": meta,
        }
    if variants:
        _rewrite(os.path.join(outdir, "13-x-codex-turn-metadata-decoded.json"), {
            "_note":
                "x-codex-turn-metadata decoded, one entry per handshake variant in this capture. "
                "Field ORDER in the source string is significant and is preserved here. Deltas vs "
                "codexapp0.147.0, which emitted only installation_id, session_id, thread_id, "
                "turn_id, window_id, request_kind, thread_source, sandbox: agent_name is new after "
                "thread_id; window_number and context_window_id are new after window_id; "
                "sandbox_mode, auto_review_enabled, node_repl_auto_review_required and "
                "node_repl_disabled are new after sandbox. A subagent connection inserts "
                "parent_thread_id and subagent_kind after request_kind. agent_name was literally "
                "\"/root\" here — it is the client's working directory, so a proxy has no honest "
                "value for it; kept unmasked only because it is not a secret.",
            "variants": variants,
        })


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    dump_path = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(CRACK_ROOT, "codexv0.153.4", "rows")
    os.makedirs(outdir, exist_ok=True)

    with open(dump_path) as fh:
        dump = json.load(fh)
    sessions = dump.get("data", {}).get("data")
    if not isinstance(sessions, dict):
        sys.exit("unrecognised dump shape: expected obj['data']['data'] to be a dict of sessions")
    rows = sorted(sessions.values(), key=lambda s: s.get("startTime", 0))
    print("read %d sessions from %s" % (len(rows), dump_path))

    red = Redactor()
    # Seed the well-known identity values so they get readable placeholders
    # rather than <UUID_7>.
    for session in rows:
        headers = (session.get("req") or {}).get("headers") or {}
        acct = headers.get("chatgpt-account-id")
        if acct and acct not in red.map:
            red.map[acct] = "<ACCOUNT_UUID>"
        meta = headers.get("x-codex-turn-metadata")
        if meta:
            try:
                install = json.loads(meta).get("installation_id")
                if install and install not in red.map:
                    red.map[install] = "<INSTALLATION_ID>"
            except Exception:
                pass

    counts = {}
    manifest = []
    used = set()
    for session in rows:
        url = session.get("url", "")
        method = (session.get("req") or {}).get("method")
        for pattern, needle, want_method, note in RULES:
            if needle not in url:
                continue
            if want_method and method != want_method:
                continue
            if "{n}" in pattern:
                counts[pattern] = counts.get(pattern, 0) + 1
                name = pattern.replace("{n}", "%02d" % counts[pattern])
            else:
                name = pattern
                if name in used:
                    break  # one representative row per non-{n} rule
            used.add(name)
            plugin_store = "/backend-api/ps/" in url or "/plugins/featured" in url
            row = emit(session, note, red,
                       elide_catalog=name.startswith("01-"),
                       elide_all=plugin_store)
            with open(os.path.join(outdir, name), "w") as fh:
                json.dump(row, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            manifest.append({"file": name, "url": row["url"], "method": row["method"],
                             "status": row["status"]})
            print("  wrote", name)
            break

    postprocess(outdir)

    manifest = []
    for name in sorted(os.listdir(outdir)):
        if name.startswith("_") or not name.endswith(".json"):
            continue
        with open(os.path.join(outdir, name)) as fh:
            row = json.load(fh)
        if "url" in row:
            manifest.append({"file": name, "url": row["url"],
                             "method": row["method"], "status": row["status"]})
        else:
            manifest.append({"file": name, "note": "derived companion row"})
    with open(os.path.join(outdir, "_manifest.json"), "w") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("wrote %d rows + _manifest.json to %s" % (len(manifest), outdir))


if __name__ == "__main__":
    main()
