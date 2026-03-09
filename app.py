import json
import logging
import os
import hmac
import hashlib
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

PD_API_BASE = "https://api.pagerduty.com"

PD_API_TOKEN = os.environ["PD_API_TOKEN"]          # REST API key
PD_FROM_EMAIL = os.environ["PD_FROM_EMAIL"]        # email существующего PD user
PD_WEBHOOK_SECRET = os.environ["PD_WEBHOOK_SECRET"]  # signing secret (Generic Webhooks v3)

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


def verify_webhook_signature(secret: str, raw_body: bytes, signature_header: Optional[str]) -> bool:
    if not signature_header:
        return False
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    for ver, val in _parse_pd_signatures(signature_header):
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


def extract_tags(alert: Dict[str, Any]) -> List[Any]:
    """Get tags array from alert (body.details.tags or body.tags)."""
    body = (alert or {}).get("body") or {}
    details = body.get("details") or {}
    tags = details.get("tags") or body.get("tags")
    if not isinstance(tags, list):
        return []
    return tags


def extract_check_name(alert: Dict[str, Any]) -> Optional[str]:
    body = (alert or {}).get("body") or {}
    details = body.get("details") or {}
    # частые варианты ключей в кастомных деталях
    for key in ("check_name", "check", "alertname", "rule", "name"):
        v = details.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def extract_links(alert: Dict[str, Any]) -> List[Tuple[str, str]]:
    links: List[Tuple[str, str]] = []
    body = (alert or {}).get("body") or {}
    contexts = body.get("contexts") or []
    for c in contexts:
        if not isinstance(c, dict):
            continue
        # PD: type "link" with href; some integrations use "anchor" or put URL in "url"
        href = c.get("href") or c.get("url")
        if not href or not isinstance(href, str):
            continue
        link_type = c.get("type")
        if link_type not in ("link", "anchor", None):
            continue
        text = c.get("text") or c.get("subject") or c.get("name") or "link"
        links.append((str(text), str(href)))
    return links


def _format_tag(tag: Any) -> str:
    if isinstance(tag, str):
        return tag
    if isinstance(tag, dict):
        return " ".join(f"{k}={v}" for k, v in sorted(tag.items()))
    return str(tag)


def build_note_content(
    check_name: Optional[str],
    tags: List[Any],
    links: List[Tuple[str, str]],
) -> str:
    lines: List[str] = []
    if tags:
        lines.append("Tags:")
        for tag in tags:
            lines.append(f"- {_format_tag(tag)}")
    if check_name:
        lines.append(f"check_name: {check_name}")
    if links:
        lines.append("Links:")
        for text, href in links:
            lines.append(f"- {text}: {href}")
    return "\n".join(lines)


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

    if not verify_webhook_signature(PD_WEBHOOK_SECRET, raw, x_pagerduty_signature):
        raise HTTPException(status_code=401, detail="Bad webhook signature")

    payload = await request.json()
    if LOG_WEBHOOK_JSON:
        print("[LOG_WEBHOOK_JSON] PagerDuty webhook payload:\n", json.dumps(payload, ensure_ascii=False, indent=2), flush=True)
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
        print("[LOG_ALERT_JSON] PagerDuty first alert incident_id=%s:\n" % incident_id, json.dumps(alert, ensure_ascii=False, indent=2), flush=True)
    check_name = extract_check_name(alert or {})
    tags = extract_tags(alert or {})
    links = extract_links(alert or {})

    content = build_note_content(check_name, tags, links)
    await pd_create_note(incident_id, content)

    return {"ok": True, "incident_id": incident_id, "check_name": check_name, "links": len(links)}
