"""Async watchlist scanner — fan-out search across all brands in one sweep.

Token: the marketplace issues 2-hour JWT bearer tokens (access_token_web).
Hot-reload: drop a fresh token into token.txt or cookies.json; the watcher
picks it up on the next get_token() call or within 30s if paused.

Watchlist path: set WATCHLIST_PATH env var, or place watchlist.json next to
this file (falls back to the bundled example).
"""

import asyncio
import base64
import json
import logging
import os
import random
import re
import time
from collections import deque
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional

from curl_cffi.requests import AsyncSession

LOGGER = logging.getLogger(__name__)

_seller_sem = asyncio.Semaphore(2)
_seller_cache: Dict[int, Dict[str, Any]] = {}

# -------------------------
# CONFIG
# -------------------------

@dataclass
class BrandConfig:
    name: str
    max_price: float  # GBP
    size_label: Optional[str] = "XL"  # None = any size


def _load_brands() -> List[BrandConfig]:
    p = os.getenv("WATCHLIST_PATH") or os.path.join(os.path.dirname(__file__), "watchlist.json")
    with open(p) as f:
        return [BrandConfig(**e) for e in json.load(f)]

BRANDS: List[BrandConfig] = _load_brands()

# Set ACCESS_TOKEN in env, or write to token.txt next to this file.
ACCESS_TOKEN: str = os.getenv("ACCESS_TOKEN", "")

_TOKEN_FILE = os.path.join(os.path.dirname(__file__), "token.txt")
_token_file_mtime: float = 0.0

_COOKIE_FILE = os.path.join(os.path.dirname(__file__), "cookies.json")
_cookie_file_mtime: float = 0.0

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

_ACCEPT_LANGUAGE_POOL = [
    "en-GB,en-US;q=0.9,en;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8,de;q=0.7",
    "en-US,en-GB;q=0.9,en;q=0.8",
    "en-GB,en;q=0.9",
    "en-GB,en;q=0.9,pl;q=0.8",
]

_SESSION_UA = random.choice(_USER_AGENTS)


def _curl_impersonate() -> str:
    if "Chrome/" in _SESSION_UA:
        m = re.search(r"Chrome/(\d+)", _SESSION_UA)
        v = int(m.group(1)) if m else 124
        return "chrome124" if v <= 124 else "chrome131"
    if "Firefox/" in _SESSION_UA:
        return "firefox133"
    if "Safari/" in _SESSION_UA:
        return "safari17_0"
    return "chrome124"

_IMPERSONATE = _curl_impersonate()


def _base_headers() -> dict:
    h = {
        "User-Agent": _SESSION_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": random.choice(_ACCEPT_LANGUAGE_POOL),
        "Referer": "https://www.vinted.co.uk/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }
    if "Chrome/" in _SESSION_UA:
        m = re.search(r"Chrome/(\d+)", _SESSION_UA)
        v = m.group(1) if m else "125"
        platform = '"macOS"' if "Macintosh" in _SESSION_UA else '"Windows"'
        h["Sec-Ch-Ua"] = f'"Google Chrome";v="{v}", "Chromium";v="{v}", "Not.A/Brand";v="24"'
        h["Sec-Ch-Ua-Mobile"] = "?0"
        h["Sec-Ch-Ua-Platform"] = platform
    return h

POLL_MIN = 7
POLL_MAX = 18
SEARCH_TIMEOUT_SECONDS = 12.0

TOKEN_EXPIRY_MARGIN = 120


# -------------------------
# SHARED CLIENT + TOKEN LOCK
# -------------------------

_client: Optional[AsyncSession] = None
_token: str = ACCESS_TOKEN
_token_exp: float = 0.0


def _load_cookie_jar() -> Dict[str, str]:
    """Parse EditThisCookie JSON export → {name: value} dict."""
    try:
        with open(_COOKIE_FILE) as f:
            data = json.load(f)
        if isinstance(data, list):
            return {c["name"]: c["value"] for c in data if "name" in c and "value" in c}
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _maybe_reload_cookie_jar() -> None:
    global _cookie_file_mtime
    try:
        mtime = os.path.getmtime(_COOKIE_FILE)
    except OSError:
        return
    if mtime <= _cookie_file_mtime:
        return
    jar = _load_cookie_jar()
    if not jar:
        return
    _cookie_file_mtime = mtime
    if _client is not None:
        for name, value in jar.items():
            _client.cookies[name] = value
    token_val = jar.get("access_token_web", "")
    if token_val:
        load_token(token_val)
    LOGGER.info("[COOKIES] jar reloaded (%d cookies)", len(jar))


def _get_client() -> AsyncSession:
    global _client
    if _client is None:
        _client = AsyncSession(impersonate=_IMPERSONATE)
        jar = _load_cookie_jar()
        if jar:
            for name, value in jar.items():
                _client.cookies[name] = value
            LOGGER.debug("[COOKIES] %d cookies loaded into session", len(jar))
    return _client


async def aclose() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None


# -------------------------
# TOKEN KNOCK-WAIT
# -------------------------

def _token_live() -> bool:
    return bool(_token) and time.time() < (_token_exp - TOKEN_EXPIRY_MARGIN)


def _parse_exp(token: str) -> float:
    """Decode exp claim from a JWT without a third-party library."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
    except Exception:
        return 0.0


def _maybe_reload_token_from_file() -> None:
    global _token_file_mtime
    try:
        mtime = os.path.getmtime(_TOKEN_FILE)
    except OSError:
        return
    if mtime <= _token_file_mtime:
        return
    try:
        raw = open(_TOKEN_FILE).read().strip()
    except OSError:
        return
    if raw:
        _token_file_mtime = mtime
        load_token(raw)
        LOGGER.info("[TOKEN] hot-reloaded from token.txt")


_SESSION_COOKIES = {
    "access_token_web", "refresh_token_web",
    "_vinted_fr_session", "v_sid", "v_udt", "v_uid",
}


def _jwt_sid(token: str) -> str:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("sid", "")
    except Exception:
        return ""


def load_token(raw: str) -> None:
    """Accept a freshly pasted token and update module state."""
    global _token, _token_exp
    _token = raw.strip()
    _token_exp = _parse_exp(_token)
    LOGGER.info("[TOKEN] loaded, exp in %.0fs", _token_exp - time.time())
    if _client is not None:
        jar_sid = _client.cookies.get("v_sid", "")
        token_sid = _jwt_sid(_token)
        if jar_sid and token_sid and jar_sid != token_sid:
            for name in _SESSION_COOKIES:
                try:
                    del _client.cookies[name]
                except KeyError:
                    pass
            LOGGER.info("[COOKIES] session mismatch — stale session cookies cleared")


def token_expires_in() -> float:
    """Seconds until token expires. Negative if already expired."""
    return _token_exp - time.time()


async def get_token() -> str:
    _maybe_reload_cookie_jar()
    _maybe_reload_token_from_file()
    if _token_live():
        return _token
    raise RuntimeError("Token expired — paste cookies.json or token.txt")


def invalidate_token() -> None:
    """Force a re-prompt on next get_token() call (e.g. after a 401)."""
    global _token_exp
    _token_exp = 0.0


# -------------------------
# SEARCH & FILTER
# -------------------------

_GARMENT_HINTS = ["jacket", "coat", "shirt", "long sleeve", "hoodie", "polo"]
_VAGUE_INTENTS  = ["top", "clothes", "mens wear", "xl top"]
_GENDER_HINTS   = ["mens", "men's"]

_CATEGORY_MOODS: List[List[str]] = [
    ["jacket", "coat", "overshirt", "gilet"],
    ["shirt", "flannel", "button up", "oxford"],
    ["hoodie", "sweatshirt", "fleece", "knitwear"],
    ["t-shirt", "tee", "polo", "long sleeve"],
]
_sweep_garment_hints: List[str] = _GARMENT_HINTS

# Size drift: 70% XL, 15% L, 15% XXL
_SIZE_DRIFT = [(0.70, 206), (0.15, 205), (0.15, 207)]

def _pick_size_id() -> int:
    weights, ids = zip(*_SIZE_DRIFT)
    return random.choices(ids, weights=weights)[0]

_DRIFT_BRANDS = [
    "Nike", "Adidas", "Ralph Lauren", "Tommy Hilfiger", "Levi's",
    "Stone Island", "New Balance", "Carhartt", "The North Face", "Ellesse",
    "Superdry", "Polo Sport", "Lacoste", "Under Armour",
]


def _misspell(s: str) -> str:
    if len(s) < 5:
        return s
    i = random.randint(1, len(s) - 2)
    return s[:i] + s[i + 1:]


def _choose_query_shape(brand: BrandConfig) -> str:
    n = brand.name.lower()
    sz = (brand.size_label or "xl").lower()
    shapes  = [n, f"{n} {sz}", f"{n} {random.choice(_sweep_garment_hints)}", f"{n} {random.choice(_GENDER_HINTS)}", f"{_misspell(n)} {sz}", f"{n} {random.choice(_VAGUE_INTENTS)}"]
    weights = [0.40, 0.25, 0.15, 0.10, 0.05, 0.05]
    base = random.choices(shapes, weights=weights)[0]

    if random.random() < 0.12:
        tokens = base.split()
        if len(tokens) > 1 and random.random() < 0.4:
            base = " ".join(tokens[:-1])
        elif random.random() < 0.3:
            base = f"{base} {random.choice(_sweep_garment_hints)}"

    return base


async def search_brand(brand: BrandConfig, token: str, query: Optional[str] = None) -> List[Dict[str, Any]]:
    client = _get_client()
    resp = await client.get(
        "https://www.vinted.co.uk/api/v2/catalog/items",
        headers={**_base_headers(), "Authorization": f"Bearer {token}"},
        params={
            "search_text": query or brand.name,
            "order": "newest_first",
            "per_page": 50,
            "size_id": _pick_size_id(),
            "catalog_ids": 5,
        },
        timeout=15.0,
    )
    if resp.status_code in (401, 403):
        invalidate_token()
        raise PermissionError(f"{resp.status_code} on search for {brand.name}")
    resp.raise_for_status()
    return resp.json().get("items", [])


_WOMENS_KEYWORDS = {"women", "ladies", "girl", "baby", "kids", "skirt"}
_ACCESSORY_KEYWORDS = {"bag", "sling", "daypack", "hat", "bum bag", "sticker"}
_TITLE_SIZE_WORDS = {"xl": "xl", "l": "large", "m": "medium", "s": "small"}
_WOMENS_UK_SIZE_RE = re.compile(r"uk\s*(?:1\d|2\d)", re.IGNORECASE)


def _size_matches(item: Dict[str, Any], target: str) -> bool:
    size = (item.get("size_title") or "").lower()
    title = (item.get("title") or "").lower()
    t = target.lower()

    if any(w in title for w in _ACCESSORY_KEYWORDS):
        return False
    if any(w in title for w in _WOMENS_KEYWORDS):
        return False
    if _WOMENS_UK_SIZE_RE.search(size):
        return False

    if size:
        return size == t or size.startswith(t + " ") or size.startswith(t + "/")

    word = _TITLE_SIZE_WORDS.get(t)
    return bool(word and word in title)


def _brand_relevance(item: Dict[str, Any], brand: BrandConfig) -> float:
    title = (item.get("title") or "").lower()
    b = brand.name.lower()
    if b in title:
        return 1.0
    sim = SequenceMatcher(None, title, b).ratio()
    sim2 = SequenceMatcher(None, title.replace(" ", ""), b.replace(" ", "")).ratio()
    return max(sim, sim2)


def _value_score(price: float, max_price: float) -> float:
    if max_price <= 0:
        return 0.0
    return round(max((max_price - price) / max_price, 0.0), 2)


_REL_THRESHOLD = 0.60


def _filter(items: List[Dict[str, Any]], brand: BrandConfig) -> List[Dict[str, Any]]:
    results = []
    for i in items:
        rel = _brand_relevance(i, brand)
        if rel < _REL_THRESHOLD:
            continue
        if brand.size_label and not _size_matches(i, brand.size_label):
            continue
        price = _safe_price(i)
        if price > brand.max_price:
            continue
        i["_rel"] = round(rel, 2)
        i["_value"] = _value_score(price, brand.max_price)
        results.append(i)
    return results


# -------------------------
# FAN-OUT SWEEP
# -------------------------

async def _human_search_brand(brand: BrandConfig, token: str) -> tuple[BrandConfig, List[Dict[str, Any]]]:
    await asyncio.sleep(random.uniform(0.4, 2.2))

    if random.random() < 0.05:
        LOGGER.info("[DRIFT] skipped %s this sweep", brand.name)
        return brand, []

    items = await search_brand(brand, token, query=_choose_query_shape(brand))

    if items and all(
        _safe_price(i) > brand.max_price for i in items[:5]
    ):
        await asyncio.sleep(random.uniform(1.0, 3.0))

    return brand, _filter(items, brand)


def _safe_price(item: Dict[str, Any]) -> float:
    try:
        return float(item.get("price", {}).get("amount", 0))
    except (ValueError, TypeError):
        return 0.0


async def _search_timed(brand: BrandConfig, token: str) -> tuple[BrandConfig, List[Dict[str, Any]]]:
    try:
        brand, candidates = await asyncio.wait_for(
            _human_search_brand(brand, token), timeout=SEARCH_TIMEOUT_SECONDS
        )
        LOGGER.info("[SCAN] %s → %d candidates", brand.name, len(candidates))
        return brand, candidates
    except asyncio.TimeoutError:
        LOGGER.warning("[TIMEOUT] %s", brand.name)
        return brand, []
    except Exception as exc:
        LOGGER.error("[ERROR] %s: %s", brand.name, exc)
        return brand, []


async def fetch_seller(user_id: int, token: str) -> Dict[str, Any]:
    if user_id in _seller_cache:
        return _seller_cache[user_id]
    client = _get_client()
    async with _seller_sem:
        if user_id in _seller_cache:
            return _seller_cache[user_id]
        await asyncio.sleep(random.uniform(0.5, 1.2))
        try:
            resp = await client.get(
                f"https://www.vinted.co.uk/api/v2/users/{user_id}",
                headers={**_base_headers(), "Authorization": f"Bearer {token}"},
                timeout=8.0,
            )
            if resp.status_code == 200:
                profile = resp.json().get("user", {})
                _seller_cache[user_id] = profile
                return profile
        except Exception as exc:
            LOGGER.debug("[SELLER] fetch failed for %s: %s", user_id, exc)
    return {}


def seller_trust(profile: Dict[str, Any]) -> float:
    rep = float(profile.get("feedback_reputation", 0))
    sales = profile.get("feedback_count", 0)
    if sales >= 200:
        sales_w = 1.0
    elif sales >= 50:
        sales_w = 0.7
    elif sales >= 10:
        sales_w = 0.4
    else:
        sales_w = 0.2
    verified = 0.1 if profile.get("is_verified") else 0.0
    return max(0.1, min(1.0, rep * 0.7 + sales_w * 0.2 + verified * 0.1))


async def _fire_drift_brand(token: str) -> None:
    """Browse a random non-watchlist brand to vary the search pattern."""
    brand = random.choice(_DRIFT_BRANDS)
    client = _get_client()
    try:
        await client.get(
            "https://www.vinted.co.uk/api/v2/catalog/items",
            headers={**_base_headers(), "Authorization": f"Bearer {token}"},
            params={
                "search_text": brand.lower(),
                "order": "newest_first",
                "per_page": 20,
                "size_id": _pick_size_id(),
                "catalog_ids": 5,
            },
            timeout=8.0,
        )
        LOGGER.debug("[DRIFT] hopped to %s", brand)
    except Exception:
        pass


async def _land_on_homepage(token: str) -> None:
    """Fetch the main feed before starting brand searches."""
    client = _get_client()
    try:
        await client.get(
            "https://www.vinted.co.uk/api/v2/catalog/items",
            headers={**_base_headers(), "Authorization": f"Bearer {token}"},
            params={"order": "newest_first", "per_page": 20},
            timeout=8.0,
        )
        LOGGER.debug("[LAND] homepage hit")
    except Exception:
        pass
    await asyncio.sleep(random.uniform(2.5, 6.0))


async def sweep() -> List[tuple[BrandConfig, Dict[str, Any]]]:
    global _sweep_garment_hints
    _seller_cache.clear()
    token = await get_token()
    _sweep_garment_hints = random.choice(_CATEGORY_MOODS)
    LOGGER.debug("[MOOD] %s", _sweep_garment_hints)
    await _land_on_homepage(token)
    pool = random.sample(BRANDS, k=random.randint(6, len(BRANDS)))
    results = []
    drift_budget = random.randint(0, 2)
    drift_spent = 0
    for b in pool:
        results.append(await _search_timed(b, token))
        await asyncio.sleep(random.uniform(4, 14))
        if drift_spent < drift_budget and random.random() < 0.25:
            await _fire_drift_brand(token)
            drift_spent += 1
            await asyncio.sleep(random.uniform(3, 8))
    candidates = [(brand, item) for brand, items in results for item in items]

    uid_best_val: Dict[int, float] = {}
    for _, item in candidates:
        uid = (item.get("user") or {}).get("id")
        if uid:
            uid_best_val[uid] = max(uid_best_val.get(uid, 0.0), item.get("_value", 0.0))
    SELLER_BUDGET = random.randint(18, 25)
    ordered_ids = sorted(uid_best_val, key=uid_best_val.__getitem__, reverse=True)[:SELLER_BUDGET]

    profiles: Dict[int, Dict[str, Any]] = {}
    for profile in await asyncio.gather(*(fetch_seller(uid, token) for uid in ordered_ids)):
        uid = profile.get("id")
        if uid:
            profiles[uid] = profile

    out = []
    for brand, item in candidates:
        uid = (item.get("user") or {}).get("id")
        profile = profiles.get(uid, {})
        if profile:
            item["_trust"] = round(seller_trust(profile), 2)
            item["_seller_sales"] = profile.get("feedback_count", 0)
            item["_seller_rep"] = profile.get("feedback_reputation", 0)
        else:
            item["_trust"] = 0.1
        if item["_trust"] >= 0.35:
            out.append((brand, item))
    return out


# -------------------------
# NUGGET DETECTION
# -------------------------

NUGGET_VAL   = 0.40
NUGGET_REL   = 1.00
NUGGET_TRUST = 0.70

_alerted_ids: deque = deque(maxlen=5000)


def is_nugget(item: Dict[str, Any]) -> bool:
    return (
        item.get("_value", 0)   >= NUGGET_VAL
        and item.get("_rel", 0) >= NUGGET_REL
        and item.get("_trust", 0) >= NUGGET_TRUST
    )


def format_nugget_alert(brand: "BrandConfig", item: Dict[str, Any]) -> str:
    price  = item.get("price", {}).get("amount", "?")
    val    = item.get("_value", 0)
    trust  = item.get("_trust", 0)
    size   = item.get("size_title", "?")
    title  = item.get("title", "?")
    url    = item.get("url", f"https://www.vinted.co.uk/items/{item['id']}")
    return (
        f"🔥 *Nugget detected ({brand.name})*\n"
        f"£{price} — val={val:.2f} — trust={trust:.2f} — {size}\n"
        f"{title}\n"
        f"{url}"
    )


async def nugget_loop(send_fn, interval_min: int = 8, interval_max: int = 20) -> None:
    """
    Background loop: sweep every ~10 minutes, call send_fn(text) for each
    new nugget. Pass a coroutine function that accepts a single string.
    """
    LOGGER.info("[NUGGET] loop started")
    while True:
        try:
            candidates = await sweep()
            for brand, item in candidates:
                item_id = item.get("id")
                if not item_id or item_id in _alerted_ids:
                    continue
                if is_nugget(item):
                    msg = format_nugget_alert(brand, item)
                    LOGGER.info("[NUGGET] %s £%s", brand.name, item.get("price", {}).get("amount"))
                    await send_fn(msg)
                    _alerted_ids.append(item_id)
        except (RuntimeError, PermissionError) as exc:
            LOGGER.warning("[NUGGET] paused: %s", exc)
            invalidate_token()
            while not _token_live():
                _maybe_reload_token_from_file()
                _maybe_reload_cookie_jar()
                await asyncio.sleep(30)
            LOGGER.info("[NUGGET] token refreshed, resuming")
            continue
        except Exception as exc:
            LOGGER.error("[NUGGET] sweep error: %s", exc)

        delay = random.uniform(interval_min * 60, interval_max * 60)
        LOGGER.info("[NUGGET] next sweep in %.0fs", delay)
        await asyncio.sleep(delay)


# -------------------------
# MAIN LOOP
# -------------------------

async def dry_run_sweep() -> None:
    """Log all candidates without firing alerts. Useful for tuning thresholds."""
    if ACCESS_TOKEN:
        load_token(ACCESS_TOKEN)

    while True:
        try:
            candidates = await sweep()
            LOGGER.info("[SWEEP] %d candidates across all brands", len(candidates))
            for brand, item in candidates:
                nugget_flag = " NUGGET" if is_nugget(item) else ""
                LOGGER.info("[CANDIDATE%s] %s £%s %s", nugget_flag, brand.name, item.get("price", {}).get("amount"), item.get("title", ""))
        except Exception as exc:
            LOGGER.error("[DRY RUN] sweep error: %s", exc)

        sweep_delay = random.uniform(POLL_MIN, POLL_MAX)
        LOGGER.info("[SWEEP DONE] sleeping %.1fs", sweep_delay)
        await asyncio.sleep(sweep_delay)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(dry_run_sweep())
