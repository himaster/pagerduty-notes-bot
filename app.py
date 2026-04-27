import json
import logging
import os
import hmac
import hashlib
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PD_API_BASE = "https://api.pagerduty.com"
SLACK_API_BASE = "https://slack.com/api"

PD_API_TOKEN = os.environ["PD_API_TOKEN"]          # REST API key
PD_FROM_EMAIL = os.environ["PD_FROM_EMAIL"]        # email существующего PD user
PD_WEBHOOK_SECRETS = [
    s.strip() for s in os.environ["PD_WEBHOOK_SECRET"].split(",") if s.strip()
]

# опционально: bot token для резолва Slack user group по handle (нужен scope usergroups:read)
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "").strip() or None

# опционально: чтобы не спамить нотами на ретраях
DEDUP_ENABLED = os.getenv("DEDUP_ENABLED", "true").lower() == "true"

# Debug logging flags (enable temporarily in prod)
LOG_WEBHOOK_JSON = os.getenv("LOG_WEBHOOK_JSON", "false").lower() == "true"
LOG_ALERT_JSON = os.getenv("LOG_ALERT_JSON", "false").lower() == "true"

app = FastAPI(title="pagerduty-slack-thread-enricher", version="1.0.0")


@app.exception_handler(HTTPException)
async def log_http_exception(request: Request, exc: HTTPException):
    """Log HTTPException detail so 4xx/5xx errors are visible in logs."""
    level = logging.ERROR if exc.status_code >= 500 else logging.WARNING
    logger.log(
        level,
        "HTTPException path=%s status=%s detail=%s",
        request.url.path,
        exc.status_code,
        exc.detail,
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


def _parse_pd_signatures(header_value: str) -> List[Tuple[str, str]]:
    # "v1=abc, v1=def" -> [("v1","abc"),("v1","def")]
    parts = [p.strip() for p in header_value.split(",") if p.strip()]
    out: List[Tuple[str, str]] = []
    for p in parts:
        if "=" not in p:
            continue
        ver, val = p.split("=", 1)
        out.append((ver.strip(), val.strip()))
    return out


def verify_webhook_signature(secrets: List[str], raw_body: bytes, signature_header: Optional[str]) -> bool:
    if not signature_header:
        return False
    sigs = _parse_pd_signatures(signature_header)
    for secret in secrets:
        digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        for ver, val in sigs:
            if ver == "v1" and hmac.compare_digest(val.lower(), digest.lower()):
                return True
    return False


def pd_headers() -> Dict[str, str]:
    return {
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Authorization": f"Token token={PD_API_TOKEN}",
        "Content-Type": "application/json",
        "From": PD_FROM_EMAIL,
    }


async def pd_get_first_alert(incident_id: str) -> Optional[Dict[str, Any]]:
    url = f"{PD_API_BASE}/incidents/{incident_id}/alerts"
    params = {"limit": 1, "offset": 0}
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(url, headers=pd_headers(), params=params)
        if r.status_code >= 400:
            return None
        data = r.json()
        alerts = data.get("alerts") or []
        return alerts[0] if alerts else None


def extract_check_name(alert: Dict[str, Any]) -> Optional[str]:
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    details = cef.get("details") or body.get("details") or {}
    for key in ("check_name", "check", "alertname", "rule", "name"):
        v = details.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def extract_firing(alert: Dict[str, Any]) -> Optional[str]:
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    details = cef.get("details") or {}
    firing = details.get("firing")
    if not isinstance(firing, str) or not firing.strip():
        return None
    # Drop trailing "Source: ..." line
    lines = firing.strip().splitlines()
    while lines and lines[-1].startswith("Source:"):
        lines.pop()
    return "\n".join(lines).strip() or None


def extract_tags(alert: Dict[str, Any]) -> List[str]:
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    details = cef.get("details") or body.get("details") or {}
    tags = details.get("tags")
    if isinstance(tags, list):
        return [str(t) for t in tags if t]
    return []


# Pingdom alerts carry plain string tags like "global-integration-aviatrix";
# any tag with one of these prefixes routes the ping to a fixed handle.
PINGDOM_INTEGRATION_TAG_PREFIXES = ("global-integration-", "gb-integration-")
PINGDOM_INTEGRATION_TEAM_HANDLE = "support-team"

# Note text appended for each detection case. `{mention}` is replaced with
# the resolved `<!subteam^...>` syntax just before posting.
DEFAULT_MENTION_TEMPLATE = "cc {mention}"
INTEGRATION_TEAM_MENTION_TEMPLATE = (
    "Наблюдается проблема c интеграцией с партнером, "
    "проверьте пожалуйста логи и напишите партнеру {mention}"
)


def extract_slack_team(alert: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Return (Slack user-group handle, mention message template) or None.

    Resolution order:
    1. `slack-team` / `slack_team` key in details
    2. tag formatted as `slack-team:foo` / `slack-team=foo`
    3. Pingdom-style integration tag (`global-integration-*` or
       `gb-integration-*`) -> `integration-team` with a partner-integration
       message instead of the default `cc` line.
    """
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    details = cef.get("details") or body.get("details") or {}

    for key in ("slack-team", "slack_team"):
        v = details.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lstrip("@"), DEFAULT_MENTION_TEMPLATE

    tags = details.get("tags")
    if isinstance(tags, list):
        for t in tags:
            if not isinstance(t, str):
                continue
            for sep in (":", "="):
                if sep in t:
                    k, v = t.split(sep, 1)
                    if k.strip().lower() in ("slack-team", "slack_team") and v.strip():
                        return v.strip().lstrip("@"), DEFAULT_MENTION_TEMPLATE
                    break

        for t in tags:
            if not isinstance(t, str):
                continue
            tl = t.strip().lower()
            if any(tl.startswith(p) for p in PINGDOM_INTEGRATION_TAG_PREFIXES):
                return PINGDOM_INTEGRATION_TEAM_HANDLE, INTEGRATION_TEAM_MENTION_TEMPLATE
    return None


_slack_usergroup_cache: Dict[str, str] = {}


async def slack_get_usergroup_id(handle: str) -> Optional[str]:
    """Resolve Slack user-group handle (without leading @) to its ID.

    Caches the entire usergroups list per process; on cache miss for a given
    handle the list is refetched (handles new groups created after startup).
    Requires `usergroups:read` scope on SLACK_BOT_TOKEN.
    """
    if not SLACK_BOT_TOKEN:
        return None
    h = handle.lstrip("@").strip()
    if not h:
        return None
    cached = _slack_usergroup_cache.get(h)
    if cached:
        return cached

    url = f"{SLACK_API_BASE}/usergroups.list"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(url, headers=headers)
    if r.status_code >= 400:
        logger.warning("Slack usergroups.list HTTP %s: %s", r.status_code, r.text)
        return None
    data = r.json()
    if not data.get("ok"):
        logger.warning("Slack usergroups.list error: %s", data.get("error"))
        return None
    for ug in data.get("usergroups") or []:
        ug_handle = ug.get("handle")
        ug_id = ug.get("id")
        if ug_handle and ug_id:
            _slack_usergroup_cache[ug_handle] = ug_id
    return _slack_usergroup_cache.get(h)


def extract_links(alert: Dict[str, Any]) -> List[Tuple[str, str]]:
    links: List[Tuple[str, str]] = []
    body = (alert or {}).get("body") or {}
    contexts = body.get("contexts") or []
    for c in contexts:
        if not isinstance(c, dict):
            continue
        href = c.get("href") or c.get("url")
        if not href or not isinstance(href, str):
            continue
        text = c.get("text") or c.get("subject") or c.get("name") or "link"
        links.append((str(text), str(href)))
    return links


async def pd_create_note(incident_id: str, content: str) -> None:
    url = f"{PD_API_BASE}/incidents/{incident_id}/notes"
    payload = {"note": {"content": content}}
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(url, headers=pd_headers(), json=payload)
        if r.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"PagerDuty note create failed: {r.status_code} {r.text}")


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/status")
def status():
    return "ok"


@app.get("/health")
def health():
    return "ok"


@app.post("/webhook/pagerduty")
async def pagerduty_webhook(
    request: Request,
    x_pagerduty_signature: Optional[str] = Header(default=None),
    x_webhook_id: Optional[str] = Header(default=None),  # useful for dedup/debug
):
    raw = await request.body()

    if not verify_webhook_signature(PD_WEBHOOK_SECRETS, raw, x_pagerduty_signature):
        raise HTTPException(status_code=401, detail="Bad webhook signature")

    payload = await request.json()
    if LOG_WEBHOOK_JSON:
        logger.info("[WEBHOOK_JSON] PagerDuty webhook payload:\n%s", json.dumps(payload, ensure_ascii=False, indent=2))
    event = (payload or {}).get("event") or {}
    event_type = event.get("event_type")

    # мы реагируем только на incident.triggered (ты это и хотел)
    if event_type != "incident.triggered":
        return JSONResponse({"ignored": True, "event_type": event_type})

    incident = (event.get("data") or {})
    incident_id = incident.get("id")

    if not incident_id:
        raise HTTPException(status_code=400, detail="No incident id in payload")

    # простейшая дедупликация: если PD ретраит один и тот же webhook,
    # можно не плодить одинаковые ноты (но без внешнего стораджа это ограниченно).
    # Реально нормальная дедупликация = хранить x_webhook_id где-то.
    if DEDUP_ENABLED and x_webhook_id:
        # без стораджа это просто хук на будущее, тут ничего не делаем
        pass

    alert = await pd_get_first_alert(incident_id)
    if LOG_ALERT_JSON:
        logger.info("[ALERT_JSON] PagerDuty first alert incident_id=%s:\n%s", incident_id, json.dumps(alert, ensure_ascii=False, indent=2))
    check_name = extract_check_name(alert or {})
    firing = extract_firing(alert or {})
    tags = extract_tags(alert or {})
    links = extract_links(alert or {})
    team_info = extract_slack_team(alert or {})

    slack_message: Optional[str] = None
    if team_info:
        handle, template = team_info
        group_id = await slack_get_usergroup_id(handle)
        if group_id:
            slack_message = template.format(mention=f"<!subteam^{group_id}>")
        else:
            logger.warning(
                "Could not resolve Slack team handle '%s' to user-group ID (incident=%s)",
                handle,
                incident_id,
            )

    parts: list[str] = []
    if check_name:
        parts.append(f"check_name: {check_name}")
    if tags:
        parts.append(f"tags: {', '.join(tags)}")
    if firing:
        parts.append(firing)
    if links:
        parts.append("Links:")
        for text, href in links:
            parts.append(f"- {text}: {href}")
    if slack_message:
        parts.append(slack_message)

    if parts:
        await pd_create_note(incident_id, "\n".join(parts))

    return {"ok": True, "incident_id": incident_id}
