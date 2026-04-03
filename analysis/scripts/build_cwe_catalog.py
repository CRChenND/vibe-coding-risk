#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from cwe_reference import DEFAULT_CWE_CATALOG_CACHE, build_full_catalog_cache


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Download and cache the full MITRE CWE catalog locally.")
    p.add_argument("--out", type=Path, default=DEFAULT_CWE_CATALOG_CACHE)
    p.add_argument("--refresh", action="store_true", help="Re-download the catalog even if a cache exists.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    catalog = build_full_catalog_cache(cache_path=args.out, refresh=args.refresh)
    entries = len(catalog.get("entries") or [])
    version = catalog.get("catalog_version") or "unknown"
    print(f"Catalog entries: {entries}")
    print(f"Catalog version: {version}")
    print(f"Cache: {args.out}")


if __name__ == "__main__":
    main()
