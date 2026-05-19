import json
import logging
import os
import hmac
import hashlib
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
import yaml
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


_WEEKDAY_BY_NAME = {
    "mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
}


def _parse_tz_offset(value: str) -> timezone:
    """Parse \"+03:00\" / \"-05:30\" into a timezone."""
    if not isinstance(value, str) or len(value) < 6 or value[0] not in "+-":
        raise ValueError(f"invalid tz offset: {value!r}")
    sign = 1 if value[0] == "+" else -1
    hours, minutes = value[1:].split(":")
    return timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))


def _parse_hhmm(value: str) -> time:
    h, m = value.split(":")
    return time(int(h), int(m))


def _parse_handles(cfg: Dict[str, Any], ctx: str) -> Tuple[str, ...]:
    """Accept either `handle: str` or `handles: [str, ...]`; return non-empty tuple."""
    has_one = "handle" in cfg
    has_many = "handles" in cfg
    if has_one and has_many:
        raise ValueError(f"{ctx}: provide either 'handle' or 'handles', not both")
    if not has_one and not has_many:
        raise ValueError(f"{ctx}: must provide 'handle' or 'handles'")
    if has_many:
        raw = cfg["handles"]
        if (
            not isinstance(raw, list)
            or not raw
            or not all(isinstance(x, str) and x.strip() for x in raw)
        ):
            raise ValueError(f"{ctx}: 'handles' must be a non-empty list of strings")
        return tuple(x.strip().lstrip("@") for x in raw)
    raw = cfg["handle"]
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{ctx}: 'handle' must be a non-empty string")
    return (raw.strip().lstrip("@"),)


@dataclass(frozen=True)
class _Schedule:
    tz: timezone
    days: frozenset
    start: time
    end: time
    business_handles: Tuple[str, ...]
    off_hours_handles: Tuple[str, ...]

    def pick_handles(self) -> Tuple[str, ...]:
        now = datetime.now(self.tz)
        if now.weekday() in self.days and self.start <= now.time() < self.end:
            return self.business_handles
        return self.off_hours_handles


@dataclass(frozen=True)
class _Rule:
    name: str
    tag_prefixes: Tuple[str, ...]
    message: str
    place_at_top: bool
    schedule: Optional[_Schedule]
    static_handles: Optional[Tuple[str, ...]]

    def matches(self, tags: List[str]) -> bool:
        for t in tags:
            tl = t.strip().lower()
            if any(tl.startswith(p) for p in self.tag_prefixes):
                return True
        return False

    def pick_handles(self) -> Tuple[str, ...]:
        if self.schedule is not None:
            return self.schedule.pick_handles()
        assert self.static_handles is not None
        return self.static_handles


@dataclass(frozen=True)
class _TeamRules:
    default_message: str
    rules: Tuple[_Rule, ...]


def _load_team_rules(path: str) -> _TeamRules:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    rules: List[_Rule] = []
    for idx, raw in enumerate(data.get("rules") or []):
        name = raw.get("name") or f"rule[{idx}]"
        match = raw.get("match") or {}
        prefixes = tuple(p.lower() for p in (match.get("tag_prefixes") or []))
        if not prefixes:
            raise ValueError(f"team rule {name!r} has no match.tag_prefixes")
        message = raw.get("message")
        if not isinstance(message, str) or not message.strip():
            raise ValueError(f"team rule {name!r} has empty message")
        sched_cfg = raw.get("schedule")
        schedule: Optional[_Schedule] = None
        static_handles: Optional[Tuple[str, ...]] = None
        if sched_cfg:
            bh = sched_cfg.get("business_hours") or {}
            oh = sched_cfg.get("off_hours") or {}
            schedule = _Schedule(
                tz=_parse_tz_offset(bh["tz"]),
                days=frozenset(_WEEKDAY_BY_NAME[d.lower()] for d in bh["days"]),
                start=_parse_hhmm(bh["start"]),
                end=_parse_hhmm(bh["end"]),
                business_handles=_parse_handles(bh, f"{name}.schedule.business_hours"),
                off_hours_handles=_parse_handles(oh, f"{name}.schedule.off_hours"),
            )
        else:
            static_handles = _parse_handles(raw, name)
        rules.append(_Rule(
            name=name,
            tag_prefixes=prefixes,
            message=message.strip(),
            place_at_top=bool(raw.get("place_at_top", False)),
            schedule=schedule,
            static_handles=static_handles,
        ))
    default_message = data.get("default_message") or "cc {mention}"
    return _TeamRules(default_message=default_message, rules=tuple(rules))


_TEAM_RULES_PATH = os.getenv("TEAM_RULES_CONFIG") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "team_rules.yaml"
)
TEAM_RULES = _load_team_rules(_TEAM_RULES_PATH)
logger.info(
    "Loaded team rules from %s: %d rule(s)", _TEAM_RULES_PATH, len(TEAM_RULES.rules)
)


def extract_slack_team(alert: Dict[str, Any]) -> Optional[Tuple[Tuple[str, ...], str, bool]]:
    """Return (Slack handles, mention message template, place_at_top) or None.

    Resolution order:
    1. `slack-team` / `slack_team` key in details        -> default_message
    2. tag `slack-team:foo` / `slack-team=foo`           -> default_message
    3. First rule in team_rules.yaml whose tag_prefixes match a tag.
    """
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    details = cef.get("details") or body.get("details") or {}

    for key in ("slack-team", "slack_team"):
        v = details.get(key)
        if isinstance(v, str) and v.strip():
            return (v.strip().lstrip("@"),), TEAM_RULES.default_message, False

    tags = details.get("tags")
    if not isinstance(tags, list):
        return None

    for t in tags:
        if not isinstance(t, str):
            continue
        for sep in (":", "="):
            if sep in t:
                k, v = t.split(sep, 1)
                if k.strip().lower() in ("slack-team", "slack_team") and v.strip():
                    return (v.strip().lstrip("@"),), TEAM_RULES.default_message, False
                break

    str_tags = [t for t in tags if isinstance(t, str)]
    for rule in TEAM_RULES.rules:
        if rule.matches(str_tags):
            return rule.pick_handles(), rule.message, rule.place_at_top
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


# Keys already rendered separately (check_name/tags/firing/slack-team) or
# known Grafana internals that would just add noise to the note.
_DETAILS_SKIP_KEYS = {
    "firing", "tags",
    "check_name", "check", "alertname", "rule", "name",
    "slack-team", "slack_team",
    "__alert_rule_uid__", "__alert_rule_namespace_uid__",
    "__alerts_url__", "__value_string__", "__values__",
    "__panelId__", "__dashboardUid__", "orgId",
    "generatorURL", "grafana_url",
}


def extract_summary(alert: Dict[str, Any]) -> Optional[str]:
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    # Unified Alerting puts the human-readable title in `summary`; legacy
    # Grafana dashboard alerts put it in `description` / `message`.
    for key in ("summary", "description", "message"):
        v = cef.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def extract_details_kv(alert: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return remaining (label, value) pairs from alert details.

    Skips keys rendered elsewhere or known to be noisy so that alerts
    coming via PD Events API v2 (Grafana, generic webhooks, etc.) get
    all useful labels and annotations surfaced in the PD note.
    """
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    details = cef.get("details") or body.get("details") or {}
    if not isinstance(details, dict):
        return []
    out: List[Tuple[str, str]] = []
    for k, v in details.items():
        if not isinstance(k, str) or k in _DETAILS_SKIP_KEYS:
            continue
        if v is None:
            continue
        if isinstance(v, str):
            rendered = v.strip()
            if not rendered:
                continue
        elif isinstance(v, (dict, list)):
            try:
                rendered = json.dumps(v, ensure_ascii=False)
            except (TypeError, ValueError):
                rendered = str(v)
        else:
            rendered = str(v)
        out.append((k, rendered))
    out.sort(key=lambda kv: kv[0].lower())
    return out


def extract_grafana_link(alert: Dict[str, Any]) -> Optional[str]:
    """Return a Grafana URL surfaced anywhere in the alert payload.

    Lookup order:
    1. `cef_details.client_url` when `cef_details.client == "Grafana"` —
       this is where legacy Grafana dashboard alerts put the panel URL,
       and `contexts` is empty for that integration variant.
    2. Grafana-internal keys in details (`__alerts_url__`, `generatorURL`,
       `grafana_url`) — covers Unified Alerting and custom routes.
    """
    body = (alert or {}).get("body") or {}
    cef = body.get("cef_details") or {}
    client = cef.get("client")
    client_url = cef.get("client_url")
    if (
        isinstance(client, str)
        and client.strip().lower() == "grafana"
        and isinstance(client_url, str)
        and client_url.strip()
    ):
        return client_url.strip()
    details = cef.get("details") or body.get("details") or {}
    if isinstance(details, dict):
        for key in ("__alerts_url__", "generatorURL", "grafana_url"):
            v = details.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


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
    slack_message_at_top = False
    if team_info:
        handles, template, place_at_top = team_info
        resolved: List[str] = []
        for handle in handles:
            group_id = await slack_get_usergroup_id(handle)
            if group_id:
                resolved.append(f"<!subteam^{group_id}>")
            else:
                logger.warning(
                    "Could not resolve Slack team handle '%s' to user-group ID (incident=%s)",
                    handle,
                    incident_id,
                )
        if resolved:
            slack_message = template.format(mention=" ".join(resolved))
            slack_message_at_top = place_at_top

    parts: list[str] = []
    if slack_message and slack_message_at_top:
        parts.append(slack_message)
    if check_name:
        parts.append(f"check_name: {check_name}")
    if tags:
        parts.append(f"tags: {', '.join(tags)}")
    if firing:
        parts.append(firing)
    else:
        # Pingdom-specific `firing` block is absent for Grafana / Events API v2
        # senders, so fall back to surfacing the summary and every remaining
        # label/annotation from details.
        summary = extract_summary(alert or {})
        if summary and summary != check_name:
            parts.append(summary)
        detail_pairs = extract_details_kv(alert or {})
        if detail_pairs:
            parts.append("Details:")
            for k, v in detail_pairs:
                parts.append(f"- {k}: {v}")
        grafana_link = extract_grafana_link(alert or {})
        if grafana_link and not any(grafana_link == href for _, href in links):
            links.append(("Grafana", grafana_link))
    if links:
        parts.append("Links:")
        for text, href in links:
            parts.append(f"- {text}: {href}")
    if slack_message and not slack_message_at_top:
        parts.append(slack_message)

    if parts:
        await pd_create_note(incident_id, "\n".join(parts))

    return {"ok": True, "incident_id": incident_id}
