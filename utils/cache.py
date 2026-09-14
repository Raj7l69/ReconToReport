"""
utils/cache.py
A small JSON-file-backed cache for NVD API responses, keyed by
"product version". Avoids re-querying NVD for the same service across
runs (common when re-scanning the same target/lab), which both speeds
up repeat scans and reduces pressure on the rate limit.

Entries expire after CACHE_TTL_SECONDS so stale CVE data doesn't linger
forever (new CVEs get published for existing products regularly).
"""

import json
import time
from pathlib import Path
from utils.logger import get_logger

log = get_logger("cache")

CACHE_FILE = Path(".nvd_cache.json")
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days


class NVDCache:
    def __init__(self, cache_file: Path = CACHE_FILE):
        self.cache_file = cache_file
        self._data = self._load()

    def _load(self) -> dict:
        if self.cache_file.exists():
            try:
                return json.loads(self.cache_file.read_text())
            except json.JSONDecodeError:
                log.warning("NVD cache file corrupted, starting fresh")
        return {}

    def _flush(self):
        try:
            self.cache_file.write_text(json.dumps(self._data, indent=2))
        except OSError as e:
            log.warning(f"Could not write NVD cache: {e}")

    @staticmethod
    def _key(product: str, version: str) -> str:
        return f"{product.strip().lower()} {version.strip().lower()}".strip()

    def get(self, product: str, version: str):
        key = self._key(product, version)
        entry = self._data.get(key)
        if not entry:
            return None
        if time.time() - entry["cached_at"] > CACHE_TTL_SECONDS:
            log.debug(f"Cache entry for '{key}' expired")
            return None
        log.info(f"Cache hit for '{key}' — skipping NVD API call")
        return entry["results"]

    def set(self, product: str, version: str, results: list):
        key = self._key(product, version)
        self._data[key] = {"cached_at": time.time(), "results": results}
        self._flush()