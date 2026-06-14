# nugget

Async Vinted watchlist scanner. Fan-out search across all brands in one sweep, with seller trust scoring and nugget detection.

## Install

```
pip install "nugget @ git+https://github.com/L0NDONER/nugget.git"
```

## Quickstart

Set your token:

```
export ACCESS_TOKEN=your_bearer_token
```

Or drop a fresh `token.txt` / `cookies.json` (EditThisCookie export) next to your script — the watcher hot-reloads it.

Define your watchlist in `watchlist.json` (or set `WATCHLIST_PATH`):

```json
[
  { "name": "Patagonia", "max_price": 35, "size_label": "XL" },
  { "name": "Rab",       "max_price": 35, "size_label": "XL" }
]
```

Run the loop:

```python
import asyncio
from nugget import nugget_loop

async def notify(msg: str):
    print(msg)

asyncio.run(nugget_loop(notify))
```

## What's a nugget?

An item passes if it meets all three thresholds:

| Signal | Default |
|--------|---------|
| Value score `(max_price - price) / max_price` | ≥ 0.40 |
| Brand relevance | exact match (1.0) |
| Seller trust | ≥ 0.70 |

## API

```python
from nugget import sweep, is_nugget, format_nugget_alert, load_token, token_expires_in
```

- `sweep()` — one full fan-out across all brands; returns `[(BrandConfig, item), ...]`
- `is_nugget(item)` — True if item clears all thresholds
- `format_nugget_alert(brand, item)` — formatted alert string
- `load_token(raw)` — inject a fresh bearer token at runtime
- `token_expires_in()` — seconds until current token expires

## Dry run

```
python -m nugget.watcher
```

Logs all candidates without firing any alerts.

## License

MIT
