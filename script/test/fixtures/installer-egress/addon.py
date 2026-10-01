"""mitmproxy addon for the shipped-installer restricted-egress gate.

The gate runs the REAL patched vendored installers in a container whose only
route off the network is this proxy. The addon denies by default: a request is
forwarded only when it matches a committed exact-selection rule. GitHub release
downloads redirect to a signed, short-lived CDN URL, so a redirect target is
learned ONLY from the HTTP response to an already-allowed request -- a whole CDN
namespace is never opened up.

Deny patterns (latest/channel/dist-tag/installer bootstrap) are matched first
and logged, so a genuine "no hidden latest" claim can be checked by reading the
request log, not merely by the final installed version.

Config (mounted JSON, path in EGRESS_CONFIG):
  {"allow": [{"host": H, "path": REGEX, "method": M?}], "deny": [REGEX]}
`EGRESS_MODE=observe` logs and forwards everything (capture mode); the default
`strict` enforces the allowlist. Every decision is appended to EGRESS_LOG.
"""

import json
import os
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from mitmproxy import http

CONFIG = os.environ["EGRESS_CONFIG"]
LOG = os.environ["EGRESS_LOG"]
MODE = os.environ.get("EGRESS_MODE", "strict")

with open(CONFIG, encoding="utf-8") as handle:
    _CFG = json.load(handle)
ALLOW = _CFG["allow"]
DENY = [re.compile(pattern) for pattern in _CFG.get("deny", [])]

_allowed_urls = set()
_learned = set()


def _redact(url):
    """Log the scheme/host/path only, dropping every query value.

    A learned CDN target is normally a short-lived signed URL whose query
    carries a bearer-style secret; logging it verbatim would leak it. Full URLs
    are retained only privately in the in-memory allowlist (review F5).
    """
    parts = urlsplit(url)
    if not parts.query:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "<redacted>", ""))


def _log(entry):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(entry + "\n")


def _block(flow, reason, url):
    _log("DENY %s %s" % (reason, _redact(url)))
    flow.response = http.Response.make(
        403, b"blocked by installer-egress allowlist\n",
        {"Content-Type": "text/plain"},
    )


def request(flow):
    url = flow.request.pretty_url
    for pattern in DENY:
        if pattern.search(url):
            _block(flow, "deny-pattern", url)
            return
    if MODE == "observe":
        _log("ALLOW-OBSERVE %s" % _redact(url))
        return
    host = flow.request.pretty_host
    path = flow.request.path
    for rule in ALLOW:
        if rule["host"] != host:
            continue
        if not re.search(rule["path"], path):
            continue
        if rule.get("method") and rule["method"] != flow.request.method:
            continue
        _allowed_urls.add(url)
        _log("ALLOW %s" % _redact(url))
        return
    if url in _learned:
        _log("ALLOW-LEARNED %s" % _redact(url))
        return
    _block(flow, "unlisted", url)


def response(flow):
    if MODE == "observe":
        return
    url = flow.request.pretty_url
    if url not in _allowed_urls:
        return
    status = flow.response.status_code
    location = flow.response.headers.get("location")
    if status in (301, 302, 303, 307, 308) and location:
        target = urljoin(url, location)
        _learned.add(target)
        _log("LEARN %s" % _redact(target))
