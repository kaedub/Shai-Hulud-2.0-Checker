import re
import os
import ssl
import json
import urllib.request
from urllib.parse import quote
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

try:
    import certifi  # type: ignore
except Exception:
    certifi = None

CUTOFF = datetime(
    2025, 11, 20, 0, 0, 0, tzinfo=timezone.utc
)  # publish date cutoff (UTC)
LOCKFILE = "yarn.lock"
REPORT_FILE = "validate-dates.report.json"


def parse_lockfile(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Matches lines like:
    #   "graphql@^16.9.0":
    #   @types/node@22.1.0:
    pattern = re.compile(r'^("?)(.+?)@(.+?)\1:', re.MULTILINE)

    packages = set()
    for _, name, version_spec in pattern.findall(content):
        # version spec can be a range; yarn.lock includes the resolved version later.
        # But yarn.lock entries usually look like: graphql@16.9.0:
        # So we keep the raw spec and fix later if needed.

        # Remove quotes or whitespace
        name = name.strip().strip('"').strip("'")
        version_spec = version_spec.strip().strip('"').strip("'")

        # Version spec may contain ranges (^, ~, >, <, *, x) or npm: aliases → resolve from block
        is_range = any(c in version_spec for c in "^~><*") or ("x" in version_spec.lower())
        is_alias_spec = version_spec.startswith("npm:")
        is_alias_header = version_spec == "npm"
        if is_range or is_alias_spec or is_alias_header:
            # Find the resolved version inside the block
            version_match = re.search(
                rf'{name}@{re.escape(version_spec)}:\n[^\n]*\n\s+version "(.*?)"',
                content,
            )
            if version_match:
                version = version_match.group(1)  # may itself be an alias like npm:pkg@1.2.3
            else:
                # Skip if no resolution found
                continue
        else:
            version = version_spec

        # Normalize alias from either the spec or the resolved version
        effective_name = name
        if is_alias_spec:
            alias_target = version_spec[4:]
            if "@" in alias_target:
                effective_name = alias_target.rsplit("@", 1)[0] or name
            else:
                effective_name = alias_target or name
        # If resolved version itself is an alias (e.g., version "npm:wrap-ansi@8.1.0")
        if isinstance(version, str) and version.startswith("npm:"):
            alias_target = version[4:]
            if "@" in alias_target:
                alias_name, alias_ver = alias_target.rsplit("@", 1)
                if alias_name:
                    effective_name = alias_name
                version = alias_ver  # concrete semver for registry time lookup
        # Special-case headers like "<pkg>@npm:" where version_spec == "npm"
        # Try to pull alias from the block's resolved line: resolved "npm:<real>@<ver>"
        if version_spec == "npm" and (not isinstance(version, str) or not version.startswith("npm:")):
            block_resolved = re.search(
                rf'{re.escape(name)}@npm:\n[\s\S]*?\n\s+resolved "npm:([^@"]+)@([^"]+)"',
                content,
            )
            if block_resolved:
                alias_name, alias_ver = block_resolved.group(1), block_resolved.group(2)
                if alias_name:
                    effective_name = alias_name
                if alias_ver:
                    version = alias_ver

        packages.add((effective_name, version))

    return sorted(packages)


def retry(tries=3, delay=1.0, exceptions=(Exception,), backoff=2.0):
    """
    Decorator for retrying a function call with exponential backoff.

    :param tries: Total attempts (initial + retries)
    :param delay: Initial delay between attempts (seconds)
    :param exceptions: Exception(s) to catch for retrying
    :param backoff: Backoff multiplier for delay (e.g., 2.0 doubles the delay each retry)
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            _delay = delay
            for attempt in range(tries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == tries - 1:
                        raise
                    else:
                        print(
                            f"Retrying {func.__name__} due to {type(e).__name__}: {e} (attempt {attempt+1}/{tries})"
                        )
                        import time

                        time.sleep(_delay)
                        _delay *= backoff

        return wrapper

    return decorator


@retry(tries=3, delay=1.0, exceptions=(Exception,), backoff=2.0)
def fetch_publish_time(package: str, version: str, context: ssl.SSLContext) -> Optional[datetime]:
    # Encode package for URL; keep '@' and '/' for scoped packages
    pkg_path = quote(package, safe="@/")
    url = f"https://registry.npmjs.org/{pkg_path}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15, context=context) as resp:
            data = json.loads(resp.read().decode())
            ts = None
            time_map = data.get("time") or {}
            # direct hit
            if version in time_map:
                ts = time_map[version]
            # try without a leading 'v'
            if ts is None and version.startswith("v"):
                v2 = version[1:]
                if v2 in time_map:
                    ts = time_map[v2]
            # fallback for bare major or major.minor: pick latest matching prefix X. or X.Y.
            if ts is None:
                if re.fullmatch(r"\d+", version) or re.fullmatch(r"\d+\.\d+", version):
                    prefix = f"{version}." if "." in version else f"{version}."  # both cases same pattern
                    # filter version keys only (exclude created/modified)
                    candidates = [
                        k for k in time_map.keys()
                        if k not in ("created", "modified") and isinstance(k, str) and k.startswith(prefix)
                    ]
                    if candidates:
                        # choose candidate with the max publish datetime
                        def parse_dt(s: str) -> datetime:
                            return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
                        chosen = max(candidates, key=lambda k: parse_dt(str(time_map[k])))
                        ts = time_map[chosen]
            if ts is None:
                print(data["time"])
                return None
            # Normalize Z suffix to +00:00 for fromisoformat
            ts_norm = str(ts).replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_norm)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    except Exception as e:
        print(f"Error fetching {package}@{version}: {e}")
        raise e


def _get_ssl_context() -> ssl.SSLContext:
    try:
        if certifi is not None:
            return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    return ssl.create_default_context()


def load_report(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"cacheVersion": 1, "entries": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "entries" not in data or not isinstance(data["entries"], dict):
                data["entries"] = {}
            if "cacheVersion" not in data:
                data["cacheVersion"] = 1
            return data
    except Exception:
        return {"cacheVersion": 1, "entries": {}}


def save_report(path: str, data: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def main(lockfile: str, cutoff: datetime):
    packages = parse_lockfile(lockfile)
    print(f"Lockfile: {lockfile}")
    print(f"Cutoff: {cutoff.isoformat()}")
    print("Starting scan...\n")
    print(f"Found {len(packages)} package versions in {lockfile}")
    print(f"Checking for versions published AFTER {cutoff.isoformat()}...\n")

    report = load_report(REPORT_FILE)
    entries: Dict[str, Any] = report.get("entries", {})
    ssl_context = _get_ssl_context()

    # Pre-scan cache to summarize current status for packages in lockfile
    cached_before = 0
    cached_vulnerable = 0
    to_fetch: List[Tuple[str, str]] = []
    suspicious: List[Tuple[str, str, datetime]] = []

    for name, version in packages:
        key = f"{name}@{version}"
        cached = entries.get(key)
        published_dt: Optional[datetime] = None
        if isinstance(cached, dict) and "publishedAtIso" in cached:
            try:
                cached_iso = str(cached["publishedAtIso"])
                published_dt = datetime.fromisoformat(cached_iso.replace("Z", "+00:00"))
                if published_dt.tzinfo is None:
                    published_dt = published_dt.replace(tzinfo=timezone.utc)
            except Exception:
                published_dt = None

        if published_dt is None:
            to_fetch.append((name, version))
            continue

        if published_dt > cutoff:
            cached_vulnerable += 1
            suspicious.append((name, version, published_dt))
            entries.setdefault(key, {})["status"] = "after_cutoff"
        else:
            cached_before += 1
            entries.setdefault(key, {})["status"] = "ok"

    print(f"Before cutoff (from cache): {cached_before}")
    print(f"Vulnerable (from cache): {cached_vulnerable}\n")

    # Retry unresolved or error entries
    for name, version in to_fetch:
        key = f"{name}@{version}"
        try:
            published_dt = fetch_publish_time(name, version, ssl_context)
        except Exception as e:
            entries[key] = {
                "status": "error",
                "error": f"{type(e).__name__}: {e}",
            }
            print(f"❓ {key} — error: {type(e).__name__}: {e}")
            continue

        if published_dt is None:
            entries[key] = {
                "status": "error",
                "error": "No publish time found",
            }
            print(f"❓ {key} — error: No publish time found")
            continue

        # Cache fresh result
        entries[key] = {
            "status": "ok",
            "publishedAtIso": published_dt.astimezone(timezone.utc).isoformat(),
            "publishedDate": published_dt.date().isoformat(),
        }

        if published_dt > cutoff:
            suspicious.append((name, version, published_dt))
            entries[key]["status"] = "after_cutoff"
            print(f"⚠️⚠️⚠️ {name}@{version} — published {published_dt.isoformat()}")
        else:
            print(f"✅ {name}@{version} — published {published_dt.date().isoformat()}")

    report["entries"] = entries
    report["cutoffIso"] = cutoff.isoformat()
    report["generatedAtIso"] = datetime.now(timezone.utc).isoformat()
    save_report(REPORT_FILE, report)

    if not suspicious:
        print("\n✅ No packages were published after the cutoff date. All good.")
    else:
        print("\n❌ WARNING: Some packages were published after the cutoff date:")
        for name, version, ts in suspicious:
            print(f" - {name}@{version} on {ts.isoformat()}")


def _parse_cutoff(value: str) -> datetime:
    # Accept YYYY-MM-DD or full ISO 8601; default to UTC if naive
    v = value.strip()
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        # Try date-only
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            dt = datetime(int(v[0:4]), int(v[5:7]), int(v[8:10]), 0, 0, 0)
        else:
            raise argparse.ArgumentTypeError(f"Invalid cutoff format: {value}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check yarn.lock packages against a cutoff publish date.")
    parser.add_argument(
        "-l",
        "--lockfile",
        default=LOCKFILE,
        help="Path to yarn.lock (default: yarn.lock)",
    )
    parser.add_argument(
        "-c",
        "--cutoff",
        type=_parse_cutoff,
        default=CUTOFF,
        help='Cutoff date/time in ISO format (e.g., "2025-11-20" or "2025-11-20T00:00:00Z"). Default is current CUTOFF.',
    )
    args = parser.parse_args()
    main(args.lockfile, args.cutoff)
