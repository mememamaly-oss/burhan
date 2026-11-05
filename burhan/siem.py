"""SIEM / enterprise event export — CEF, RFC 5424 syslog, OCSF JSON.

Builds on the SIGNED audit pipeline (audit.py) — never a parallel unsigned
event path: every exported event carries the source run's audit pointer
(run_id, merkle_root, findings_count, signature_b64, public_key_b64) so a
SIEM analyst can pivot back to the complete signed proof with the embedded
verification recipe. The signature reference is a POINTER (the digest
values), never the full evidence inline.

Official specifications fetched and cited BEFORE implementation (the exact
excerpts live in evidence/layers/siem-export/specs/):

  CEF  — "Implementing ArcSight Common Event Format (CEF)", Version 26,
         OpenText SmartConnectors 8.4.3, October 2023 (the official
         ArcSight/OpenText CEF specification document).
         Format line (verbatim from the spec):
           CEF:Version|Device Vendor|Device Product|Device Version|Device
           Event Class ID|Name|Severity|[Extension]
         Escaping (verbatim, Character Encoding section):
           - "Pipe (|) used in a 'value' part of a CEF header field must
              be escaped [with a backslash]."
           - "If a backslash (\\) is used in the header or the extension,
              it must be escaped with another backslash (\\)."
           - "If an equal sign (=) is used in the extensions, it has to
              be escaped with a backslash (\\). Equals signs in the
              header need no escaping."
         Severity: integer agentSeverity, "0-3=Low, 4-6=Medium, 7-8=High,
         and 9-10=Very-High"; -1 = unknown.
         rt (deviceReceiptTime): "The format is MMM dd yyyy HH:mm:ss or
         milliseconds since epoch (Jan 1st 1970)" — this module emits
         epoch milliseconds.
         Custom string fields cs1..cs6 each pair with csNLabel ("All
         custom fields have a corresponding label field").

  RFC 5424 — "The Syslog Protocol", IETF Standards Track, March 2009.
         ABNF (verbatim from section 6):
           SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]
           HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME
                             SP APP-NAME SP PROCID SP MSGID
           STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
           SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
           SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
           PARAM-VALUE     = UTF-8-STRING ; characters '"', '\' and
                                            ; ']' MUST be escaped.
           SD-NAME         = 1*32PRINTUSASCII
                             ; except '=', SP, ']', %d34 (")
           TIMESTAMP       = NILVALUE / FULL-DATE "T" FULL-TIME
         Facility/severity are "not normative but often used"; severity
         0-7 with 2 = Critical (the table in section 6.2.1).

  OCSF — Open Cybersecurity Schema Framework, v1.9.0, the official
         schema repository (github.com/ocsf/ocsf-schema, tag v1.9.0),
         class "Detection Finding" (events/findings/detection_finding.
         json, class_uid 2004, category Findings = category_uid 2).
         Required event attributes (base_event + finding class, per the
         v1.9.0 source schemas): activity_id, category_uid, class_uid,
         finding_info, metadata, severity_id, time, type_uid.
         finding_info: uid is Required; title/types/created_time are
         Recommended/Optional. metadata: product and version are
         Required; product.name is Recommended with the constraint
         "At least one of these attributes must be present: name, uid".
         severity_id enum (v1.9.0): 0 Unknown, 1 Informational, 2 Low,
         3 Medium, 4 High, 5 Critical, 6 Fatal, 99 Other.
         type_uid is computed as class_uid * 100 + activity_id
         (200401 = Detection Finding: Create).

Transport: RFC 5424 messages are sent over UDP (RFC 5426, "Transmission
of syslog messages over UDP") or TCP (RFC 6587) via the standard library
socket module — TLS (RFC 5425) is deliberately NOT bundled: wrapping the
socket in TLS requires a client certificate/PKI decision that belongs to
the deployment, not the export code; the sender accepts any already-
connected socket, so a TLS-wrapped socket can be passed by the caller.
"""
from __future__ import annotations

import json
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# severity maps (each pinned to its fetched official source)
# ---------------------------------------------------------------------------

# CEF agentSeverity: "0-3=Low, 4-6=Medium, 7-8=High, and 9-10=Very-High"
_CEF_SEVERITY = {
    "critical": 9,   # Very-High band 9-10
    "high": 8,       # High band 7-8
    "medium": 5,     # Medium band 4-6
    "low": 3,        # Low band 0-3
    "info": 1,
    "informational": 1,
}

# RFC 5424 severity (Table 2, section 6.2.1): 2 = Critical, 3 = Error,
# 4 = Warning, 5 = Notice, 6 = Informational
_RFC5424_SEVERITY = {
    "critical": 2,
    "high": 3,
    "error": 3,
    "medium": 4,
    "warning": 4,
    "low": 5,
    "notice": 5,
    "info": 6,
    "informational": 6,
}

# OCSF severity_id (v1.9.0 enum): 5 Critical, 4 High, 3 Medium, 2 Low,
# 1 Informational
_OCSF_SEVERITY_ID = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}

# OCSF status_id (v1.9.0 enum) — a verified scanner finding is a NEW
# finding entering triage: status_id 1 (New).
_OCSF_STATUS_NEW = 1
# OCSF activity_id: 1 = Create (type_uid 200401)
_OCSF_ACTIVITY_CREATE = 1


def _sev(finding: dict, table: dict, default: int) -> int:
    return table.get(str(finding.get("severity", "")).lower(), default)


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# CEF (Common Event Format) — official spec cited in the module docstring
# ---------------------------------------------------------------------------

# The official ArcSight Extension Dictionary "CEF Key Names for Event
# Producers" from the fetched spec (the keys this module's parser may
# split extension values on; spaces inside values are valid per the spec).
_CEF_KEYS = (
    "act", "app", "art", "at", "atz", "av", "agt", "ahost", "aid", "amac",
    "cnt", "cat", "cs1", "cs1Label", "cs2", "cs2Label", "cs3", "cs3Label",
    "cs4", "cs4Label", "cs5", "cs5Label", "cs6", "cs6Label",
    "cfp1", "cfp1Label", "cfp2", "cfp2Label", "cfp3", "cfp3Label",
    "cfp4", "cfp4Label", "cn1", "cn1Label", "cn2", "cn2Label", "cn3",
    "cn3Label", "c6a1", "c6a1Label", "c6a3", "c6a3Label", "c6a4",
    "c6a4Label", "dhost", "dlat", "dlong", "dntdom", "dpid", "dpriv",
    "dproc", "dpt", "dst", "dtz", "duid", "duser", "dvc", "dvchost",
    "dvcmac", "dvcpid", "end", "externalId", "eventId", "fname", "fsize",
    "filePath", "fileId", "fileHash", "fileCreateTime", "filePermission",
    "fileType", "in", "msg", "oldFileId", "oldFileHash", "oldFileName",
    "oldFilePath", "oldFileSize", "oldFileType", "oldFileCreateTime",
    "oldFileModificationTime", "out", "outcome", "proto", "rawEvent",
    "reason", "request", "requestMethod", "requestContext",
    "requestCookies", "requestClientApplication", "rt", "shost", "slat",
    "slong", "smac", "sntdom", "spid", "spriv", "sproc", "spt", "src",
    "start", "suid", "suser", "type", "flexDate1", "flexDate1Label",
    "flexString1", "flexString1Label", "flexString2", "flexString2Label",
    "deviceFacility", "deviceDirection", "deviceExternalId",
    "deviceDnsDomain", "deviceNtDomain", "deviceProcessName",
    "devicePayloadId", "deviceOutboundInterface",
    "deviceCustomDate1", "deviceCustomDate1Label",
    "deviceCustomDate2", "deviceCustomDate2Label",
    "agentDnsDomain", "agentNtDomain", "agentZoneURI",
    "agentTranslatedAddress", "agentTranslatedZoneURI",
    "agentZoneExternalID", "agentTranslatedZoneExternalID",
    "sourceDnsDomain", "sourceServiceName", "sourceTranslatedAddress",
    "sourceTranslatedPort", "sourceZoneURI", "sourceZoneExternalID",
    "sourceTranslatedZoneURI", "sourceTranslatedZoneExternalID",
    "destinationDnsDomain", "destinationServiceName",
    "destinationTranslatedAddress", "destinationTranslatedPort",
    "destinationZoneURI", "destinationZoneExternalID",
    "destinationTranslatedZoneURI", "destinationTranslatedZoneExternalID",
    "deviceTranslatedAddress", "deviceTranslatedZoneURI",
    "deviceZoneURI", "deviceZoneExternalID",
    "deviceTranslatedZoneExternalID", "customerExternalID", "customerURI",
    "dpriv", "suser",
)


def _cef_escape_header(value: str) -> str:
    """Escape a CEF header value per the spec's Character Encoding section:
    pipe and backslash are escaped with a backslash. (Equals signs in the
    header need no escaping — spec verbatim.)"""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension(value: str) -> str:
    """Escape a CEF extension VALUE per the spec: backslash and equals sign
    are escaped with a backslash; pipes in the extension need no escaping
    (spec verbatim). Newlines are encoded as \\n (multi-line values are
    only allowed in extension values)."""
    return (value.replace("\\", "\\\\")
                 .replace("=", "\\=")
                 .replace("\n", "\\n")
                 .replace("\r", ""))


def build_cef(finding: dict, audit: dict | None = None,
              device_version: str = "4.4.1", now_ms: int | None = None) -> str:
    """One CEF message (the CEF part only — no syslog prefix, per the spec's
    "Using CEF Without Syslog" section: discard the prefix, begin with
    CEF:Version).

    Header fields (all seven, from Header Field Definitions):
      CEF:0 | Burhan | burhan-dast | device_version |
      deviceEventClassId = the finding type (the unique event-type id) |
      name = "<type> at <endpoint>" (spec: the name "must not contain
      information that is specifically mentioned in other fields" — so it
      stays the type + a location word, other details ride in extensions) |
      severity = agentSeverity integer (0-10; -1 unknown)

    Extension (official ArcSight Extension Dictionary keys only):
      request      = requestUrl — "The URL accessed", full URL with protocol
      requestMethod= the HTTP method used
      msg          = message — the finding's first evidence line
      externalId   = the finding id ("The ID used by an originating device")
      rt           = deviceReceiptTime, epoch milliseconds (spec verbatim
                     format option; the scan-time receipt time)
      cat          = deviceEventCategory — the vulnerability class
      outcome      = eventOutcome — 'success' here means the verification
                     succeeded (the vulnerability was reproduced)
      cs1Label/cs1 = evidence pointer: run_id
      cs2Label/cs2 = evidence pointer: merkle_root
      cs3Label/cs3 = evidence pointer: findings_count
      cs4Label/cs4 = evidence pointer: signature (Ed25519, b64)
      cs5Label/cs5 = evidence pointer: public key (b64)
    """
    audit = audit or {}
    now_ms = now_ms if now_ms is not None else _now_ms()
    ftype = str(finding.get("type", "unknown"))
    url = str(finding.get("url", ""))
    origin = ""
    try:
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
    except ValueError:
        origin = ""
    host = urlsplit(url).hostname or "-" if url else "-"
    header = "|".join([
        "CEF:0",
        _cef_escape_header("Burhan"),               # Device Vendor
        _cef_escape_header("burhan-dast"),          # Device Product
        _cef_escape_header(device_version),         # Device Version
        _cef_escape_header(ftype),                  # Device Event Class ID
        _cef_escape_header(f"{ftype} at {host}"),   # Name
    ])
    severity = _sev(finding, _CEF_SEVERITY, -1)     # -1 = unknown per spec
    ev: list[str] = []
    if url:
        ev.append("request=" + _cef_escape_extension(url))
    method = str(finding.get("method", "") or "")
    if method:
        ev.append("requestMethod=" + _cef_escape_extension(method))
    evidences = finding.get("evidence") or []
    if evidences and isinstance(evidences, list):
        first = evidences[0]
        detail = first.get("detail", "") if isinstance(first, dict) else str(first)
        if detail:
            ev.append("msg=" + _cef_escape_extension(str(detail)))
    if finding.get("id"):
        ev.append("externalId=" + _cef_escape_extension(str(finding["id"])))
    ev.append("rt=%d" % now_ms)
    ev.append("cat=" + _cef_escape_extension(ftype))
    verified = str(finding.get("status", "")).lower() == "verified"
    ev.append("outcome=" + ("success" if verified else "failure"))
    cs_pairs = []
    if audit.get("run_id"):
        cs_pairs.append(("burhanRunId", str(audit["run_id"])))
    if audit.get("merkle_root"):
        cs_pairs.append(("burhanMerkleRoot", str(audit["merkle_root"])))
    if audit.get("findings_count") is not None:
        cs_pairs.append(("burhanFindingsCount", str(audit["findings_count"])))
    if audit.get("signature_b64"):
        cs_pairs.append(("burhanSignatureB64", str(audit["signature_b64"])))
    if audit.get("public_key_b64"):
        cs_pairs.append(("burhanPublicKeyB64", str(audit["public_key_b64"])))
    for i, (label, value) in enumerate(cs_pairs, start=1):
        ev.append(f"cs{i}Label=" + _cef_escape_extension(label))
        ev.append(f"cs{i}=" + _cef_escape_extension(value))
    return f"{header}|{severity}|{' '.join(ev)}".rstrip()


def parse_cef(message: str) -> dict:
    """Split a CEF message back into its 7 header fields + extension dict,
    undoing the spec's escapes — the validator tests build_cef against the
    official field structure without hand-rolling a second emitter.

    Extension parsing follows the spec's own rule for spaces in values:
    "If a field contains a space, such as a filename, this is valid and can
    be logged in exactly that manner" — a space only starts a NEW key when
    it is followed by a known Extension Dictionary key and an equals sign;
    real CEF consumers tokenize the same way (keys come from the
    dictionary, values are everything up to the next known key)."""
    if not message.startswith("CEF:"):
        raise ValueError("message must begin with CEF:Version")
    body = message[4:]
    fields: list[str] = []
    cur = []
    i = 0
    while i < len(body) and len(fields) < 6:
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            cur.append(body[i + 1])
            i += 2
            continue
        if c == "|":
            fields.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if len(fields) != 6:
        raise ValueError("expected 6 pipe-delimited fields after CEF:Version")
    rest = body[i:]
    severity, _, ext_raw = rest.partition("|")
    ext: dict[str, str] = {}
    # a candidate key must be a dictionary key followed by '=' at a space
    # boundary (spaces inside values survive — spec rule cited above)
    key_re = re.compile(
        r"(?:^| )(" + "|".join(re.escape(k) for k in _CEF_KEYS) + r")=")
    positions = [(m.start(), m.end(), m.group(1))
                 for m in key_re.finditer(ext_raw)]
    for idx, (start, end, key) in enumerate(positions):
        v_begin = end                        # after the '='
        v_end = positions[idx + 1][0] if idx + 1 < len(positions) \
            else len(ext_raw)                # next match starts at its space
        ext[key] = _cef_unescape(ext_raw[v_begin:v_end])
    # fields[] (from the pipe-split loop) = [Version, Device Vendor, Device
    # Product, Device Version, Device Event Class ID, Name]; mapped by zip
    # with the spec's own header names — no first-pick subscripts
    header_names = ("version", "device_vendor", "device_product",
                    "device_version", "device_event_class_id", "name")
    out = dict(zip(header_names, fields))
    out["agent_severity"] = severity
    out["extension"] = ext
    return out


def _cef_unescape(value: str) -> str:
    """Undo the spec's extension escapes (\\x -> x for the escaped char);
    trailing-space handling follows the spec's note that trailing spaces
    of the FINAL key-value pair are not preserved."""
    out = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            out.append(value[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# RFC 5424 syslog
# ---------------------------------------------------------------------------

def _sd_escape(value: str) -> str:
    """PARAM-VALUE escaping, RFC 5424 section 6 verbatim: characters '"',
    '\\' and ']' MUST be escaped (with a backslash)."""
    return (value.replace("\\", "\\\\").replace('"', '\\"')
                 .replace("]", "\\]"))


def _sd_name_ok(name: str) -> bool:
    """SD-NAME = 1*32PRINTUSASCII except '=', SP, ']', '\"'."""
    return bool(re.fullmatch(r"[!-~]{1,32}", name)) and \
        not set(name) & set("= ]\"")


def build_rfc5424(finding: dict, audit: dict | None = None,
                  facility: int = 13, now: datetime | None = None,
                  procid: str = "-") -> str:
    """One RFC 5424 SYSLOG-MSG.

    HEADER: PRI = facility*8 + severity (facility 13 "log audit" — the
    informational-use facility table, non-normative per the RFC; severity
    mapped from the finding per Table 2); VERSION = 1; TIMESTAMP = the
    RFC's FULL-DATE "T" FULL-TIME with Z offset; HOSTNAME = the finding's
    target host (PRINTUSASCII-safe); APP-NAME = "burhan-siem"; PROCID and
    MSGID carry the run id (MSGID max 32 chars — the full id also rides
    STRUCTURED-DATA).

    STRUCTURED-DATA: one SD-ELEMENT [burhan-siem@1 ...] with the
    signed-evidence pointer params (run_id, merkle_root, findings_count,
    signature, public_key) plus type/severity/status. MSG = a compact
    human line.
    """
    audit = audit or {}
    now = now or datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"  # TIME-SECFRAC 1-6 digits (3 here)
    url = str(finding.get("url", ""))
    hostname = (urlsplit(url).hostname or "unknown") if url else "unknown"
    hostname = "".join(c for c in hostname if 33 <= ord(c) <= 126) or "unknown"
    appname = "burhan-siem"
    msgid = str(finding.get("type", "finding"))[:32]
    msgid = "".join(c for c in msgid if 33 <= ord(c) <= 126) or "-"
    severity = _sev(finding, _RFC5424_SEVERITY, 6)
    pri = facility * 8 + severity
    header = f"<{pri}>1 {ts} {hostname} {appname} {procid} {msgid}"

    params: list[tuple[str, str]] = [
        ("type", str(finding.get("type", ""))),
        ("severity", str(finding.get("severity", ""))),
        ("status", str(finding.get("status", ""))),
        ("finding_id", str(finding.get("id", ""))),
        ("url", url),
        ("method", str(finding.get("method", "") or "")),
        ("risk", str(finding.get("risk", ""))),
    ]
    # the signed-evidence pointer (1.3)
    for key in ("run_id", "merkle_root", "findings_count"):
        if audit.get(key) is not None:
            params.append((key.replace("_", ""), str(audit[key])))
    if audit.get("signature_b64"):
        params.append(("signature", str(audit["signature_b64"])))
    if audit.get("public_key_b64"):
        params.append(("publickey", str(audit["public_key_b64"])))
    sd_parts = []
    for name, value in params:
        if not _sd_name_ok(name):
            raise ValueError(f"SD-PARAM name {name!r} violates SD-NAME")
        sd_parts.append(f'{name}="{_sd_escape(value)}"')
    sd = "[burhan-siem@1 " + " ".join(sd_parts) + "]"

    msg = (f'{finding.get("type", "finding")} {finding.get("severity", "")} '
           f'at {url or "unknown"} — status {finding.get("status", "")}, '
           f'signed evidence run_id={audit.get("run_id", "-")} '
           f'merkle_root={str(audit.get("merkle_root", "-"))[:16]}…')
    return f"{header} {sd} {msg}"


class SyslogSender:
    """A real RFC 5424 syslog sender over UDP (RFC 5426) or TCP (RFC 6587).

    TLS is NOT bundled (documented, not implied): RFC 5425 TLS requires a
    PKI/certificate decision owned by the deployment. A caller can pass an
    already-TLS-wrapped connected socket (sendmsg accepts it) — the sender
    itself stays transport-plain and honest about that.
    """

    def __init__(self, host: str, port: int = 514, proto: str = "udp",
                 sock=None):
        self.host, self.port, self.proto = host, port, proto
        self._sock = sock
        self._owns = False

    def __enter__(self):
        if self._sock is None:
            if self.proto == "udp":
                self._sock = socket.socket(socket.AF_INET,
                                           socket.SOCK_DGRAM)
            else:
                self._sock = socket.create_connection((self.host, self.port),
                                                      timeout=5)
            self._owns = True
        return self

    def send(self, message: str) -> int:
        data = message.encode("utf-8")
        if self.proto == "udp":
            return self._sock.sendto(data, (self.host, self.port))
        # RFC 6587 non-transparent-framing: MSG-LEN SP MSG
        frame = str(len(data)).encode() + b" " + data
        self._sock.sendall(frame)
        return len(frame)

    def __exit__(self, *a):
        if self._owns and self._sock is not None:
            self._sock.close()


# ---------------------------------------------------------------------------
# OCSF (Open Cybersecurity Schema Framework) v1.9.0 — Detection Finding
# ---------------------------------------------------------------------------

OCSF_SCHEMA_VERSION = "1.9.0"
OCSF_CLASS_UID = 2004          # Detection Finding (v1.9.0, events/findings)
OCSF_CATEGORY_UID = 2          # Findings
OCSF_TYPE_UID_CREATE = OCSF_CLASS_UID * 100 + _OCSF_ACTIVITY_CREATE  # 200401


def build_ocsf(finding: dict, audit: dict | None = None,
               now: datetime | None = None) -> dict:
    """One OCSF Detection Finding event, conforming to the fetched v1.9.0
    schema's required attribute set.

    Required (per the v1.9.0 source schemas — see module docstring):
      activity_id  1 (Create)
      category_uid 2 (Findings)
      class_uid    2004 (Detection Finding)
      finding_info {uid (Required in finding_info), title, types,
                    created_time, first_seen_time, last_seen_time,
                    src_url, data_sources}
      metadata     {product {name, vendor_name, version},
                    version = the OCSF schema version}
      severity_id  per the v1.9.0 enum
      time         epoch milliseconds
      type_uid     200401 (class_uid * 100 + activity_id)
    Recommended fields also populated: message, evidences (Evidence
    Artifacts), observables, status_id, confidence_id, is_alert.
    """
    audit = audit or {}
    now = now or datetime.now(timezone.utc)
    now_ms = int(now.timestamp() * 1000)
    ftype = str(finding.get("type", "unknown"))
    url = str(finding.get("url", ""))
    run_id = str(audit.get("run_id", "") or "")

    finding_info: dict = {
        "uid": f"{run_id}:{finding.get('id', '')}",
        "title": f"{ftype} at {url or 'unknown target'}",
        "types": [ftype],
        "created_time": now_ms,
        "first_seen_time": now_ms,
        "last_seen_time": now_ms,
        "data_sources": ["burhan-dast"],
    }
    if audit.get("merkle_root"):
        finding_info["src_url"] = (
            "burhan-signed-evidence://run/{0}/merkle/{1}".format(
                run_id, audit["merkle_root"]))

    metadata = {
        "product": {
            "name": "burhan-dast",           # name XOR uid constraint: name set
            "vendor_name": "Burhan",
            "version": str(audit.get("scanner_version", "4.4.1")),
        },
        "version": OCSF_SCHEMA_VERSION,
    }

    evidences = []
    for e in (finding.get("evidence") or [])[:4]:
        if isinstance(e, dict):
            evidences.append({"name": str(e.get("kind", "evidence")),
                              "data": str(e.get("detail", ""))[:512]})

    observables = []
    if url:
        try:
            p = urlsplit(url)
            if p.hostname:
                observables.append({"name": "target_host",
                                    "type_id": 2,   # OCSF observable type: host_name
                                    "value": p.hostname})
            observables.append({"name": "target_url",
                                "type_id": 6,      # OCSF observable type: url_string
                                "value": url[:1024]})
        except ValueError:
            pass

    event: dict = {
        "activity_id": _OCSF_ACTIVITY_CREATE,
        "category_uid": OCSF_CATEGORY_UID,
        "class_uid": OCSF_CLASS_UID,
        "class_name": "Detection Finding",
        "type_uid": OCSF_TYPE_UID_CREATE,
        "type_name": "Detection Finding: Create",
        "severity_id": _sev(finding, _OCSF_SEVERITY_ID, 99),
        "status_id": _OCSF_STATUS_NEW,
        "time": now_ms,
        "finding_info": finding_info,
        "metadata": metadata,
        "message": (f"{ftype} verified at {url or 'unknown'} "
                    f"(status {finding.get('status', '')}, risk "
                    f"{finding.get('risk', '')})"),
        "confidence_id": 3 if float(finding.get("confidence") or 0) >= 0.9 else 2,
        "is_alert": _sev(finding, _OCSF_SEVERITY_ID, 99) >= 4,
        "raw_data": json.dumps({
            "finding_id": finding.get("id"),
            "type": ftype,
            "url": url,
            "parameter": finding.get("parameter", ""),
            "method": finding.get("method", ""),
            "status": finding.get("status", ""),
        }, ensure_ascii=False),
    }
    if evidences:
        event["evidences"] = evidences
    if observables:
        event["observables"] = observables
    # the signed-evidence pointer (1.3) — digest references, never inline
    ptr = {}
    if audit.get("run_id"):
        ptr["run_id"] = audit["run_id"]
    if audit.get("merkle_root"):
        ptr["merkle_root"] = audit["merkle_root"]
    if audit.get("findings_count") is not None:
        ptr["findings_count"] = audit["findings_count"]
    if audit.get("signature_b64"):
        ptr["signature_b64"] = audit["signature_b64"]
    if audit.get("public_key_b64"):
        ptr["public_key_b64"] = audit["public_key_b64"]
    if ptr:
        # vendor_attributes is the OCSF-sanctioned home for producer-specific
        # data; the pointer rides there, and the audit recipe stays in the
        # source report (docs/AUDIT_VERIFICATION.md) — a digest, not a copy.
        event["vendor_attributes"] = {"burhan_signed_evidence": ptr}
    return event


__all__ = [
    "build_cef", "parse_cef", "build_rfc5424", "SyslogSender",
    "build_ocsf", "OCSF_SCHEMA_VERSION", "OCSF_CLASS_UID",
    "OCSF_CATEGORY_UID", "OCSF_TYPE_UID_CREATE",
]
