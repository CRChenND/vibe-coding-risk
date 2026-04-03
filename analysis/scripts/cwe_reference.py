from __future__ import annotations

import io
import json
import re
import zipfile
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET


MITRE_CWE_URL = "https://cwe.mitre.org/data/definitions/{cwe_num}.html"
MITRE_CWE_CATALOG_URL = "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
DEFAULT_CWE_CATALOG_CACHE = Path("analysis/output/cwe_catalog_full.json")

# Fallback notes used when MITRE fetch fails. These are intentionally short and
# only cover the most common CWE labels in this repository.
LOCAL_CWE_NOTES: dict[str, str] = {
    "CWE-20": "Input is accepted too loosely, so malformed or malicious values can reach sensitive behavior.",
    "CWE-22": "Path construction or file access lets attackers influence a filesystem path unexpectedly.",
    "CWE-78": "Shell execution or command composition can turn user-controlled data into unsafe system behavior.",
    "CWE-79": "Untrusted content is rendered as HTML or JavaScript, which can enable script execution.",
    "CWE-89": "SQL text is built unsafely, which can let attacker-controlled values alter a query.",
    "CWE-94": "Code or script generation is unsafe enough that attacker-controlled content could become executable.",
    "CWE-200": "Sensitive information is exposed to a broader audience or control sphere than intended.",
    "CWE-257": "Passwords or secrets are stored or handled in a way that exposes them more than necessary.",
    "CWE-306": "A sensitive action lacks adequate authentication or access control.",
    "CWE-312": "Sensitive information is stored in cleartext or another unprotected form.",
    "CWE-319": "Sensitive data is transmitted without adequate transport protection.",
    "CWE-320": "Cryptographic material is used in an unsafe, incomplete, or incorrect way.",
    "CWE-321": "A cryptographic secret is hard-coded, making exposure effectively equivalent to key disclosure.",
    "CWE-327": "A security primitive is weak, inappropriate, or placeholder-like for real protection.",
    "CWE-400": "An operation can consume too many resources and become a denial-of-service risk.",
    "CWE-459": "Temporary or debug-oriented artifacts remain around longer than intended.",
    "CWE-502": "Untrusted serialized data can trigger unsafe object handling or code paths.",
    "CWE-522": "Credentials or key material are protected inadequately.",
    "CWE-532": "Sensitive information is written to logs or other output channels.",
    "CWE-798": "A secret, password, token, or credential-like value is embedded directly in the snippet.",
    "CWE-1104": "Dependencies or packages are pulled in a way that raises supply-chain or provenance concerns.",
}

NOISE_PREFIXES = (
    "image:",
    "section help",
    "edit custom filter",
    "conceptual",
    "operational",
    "mapping friendly",
    "select all",
    "reset",
    "clear",
    "submit",
    "cancel",
)


class _TextExtractor(HTMLParser):
    block_tags = {
        "article",
        "div",
        "p",
        "li",
        "ul",
        "ol",
        "table",
        "tr",
        "td",
        "th",
        "section",
        "header",
        "footer",
        "main",
        "aside",
        "nav",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "br",
        "hr",
    }
    skip_tags = {"script", "style", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self._buf: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.skip_tags:
            self._skip_depth += 1
            return
        if tag in self.block_tags:
            self._flush()

    def handle_endtag(self, tag: str) -> None:
        if tag in self.skip_tags and self._skip_depth:
            self._skip_depth -= 1
            return
        if tag in self.block_tags:
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if data:
            self._buf.append(data)

    def close(self) -> None:
        self._flush()
        super().close()

    def _flush(self) -> None:
        text = normalize_text("".join(self._buf))
        self._buf = []
        if text:
            self.lines.append(text)


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def split_cwe_values(raw_cwe: Any) -> list[str]:
    values = raw_cwe if isinstance(raw_cwe, list) else re.split(r"[,/;|\n]+", str(raw_cwe or ""))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        match = re.search(r"^CWE-(\d+)$", normalize_text(value), flags=re.I)
        if not match:
            continue
        cwe = f"CWE-{match.group(1)}"
        if cwe in seen:
            continue
        seen.add(cwe)
        out.append(cwe)
    return out


def tokenize_text(value: Any) -> list[str]:
    return [tok for tok in re.findall(r"[a-z0-9]+", normalize_text(value).lower()) if len(tok) >= 2]


def cwe_url(cwe: str) -> str:
    match = re.search(r"^CWE-(\d+)$", normalize_text(cwe), flags=re.I)
    if not match:
        return ""
    return MITRE_CWE_URL.format(cwe_num=match.group(1))


def _fetch_html(url: str) -> str:
    req = Request(url, headers={"User-Agent": "vibe-coding-risk/1.0"})
    with urlopen(req, timeout=30) as resp:  # nosec: trusted MITRE reference fetch
        return resp.read().decode("utf-8", errors="replace")


def _fetch_bytes(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "vibe-coding-risk/1.0"})
    with urlopen(req, timeout=60) as resp:  # nosec: trusted MITRE reference fetch
        return resp.read()


def _html_to_lines(html_text: str) -> list[str]:
    parser = _TextExtractor()
    parser.feed(html_text)
    parser.close()
    lines: list[str] = []
    for line in parser.lines:
        line = normalize_text(unescape(line))
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(NOISE_PREFIXES):
            continue
        lines.append(line)
    return lines


def _extract_section_lines(lines: list[str], heading: str, stop_headings: set[str]) -> str:
    start_idx: int | None = None
    heading_l = heading.lower()
    for idx, line in enumerate(lines):
        lower = line.lower()
        if lower == heading_l or lower.startswith(f"{heading_l} "):
            start_idx = idx + 1
            break
    if start_idx is None:
        return ""

    collected: list[str] = []
    stop_l = tuple(stop.lower() for stop in stop_headings)
    for line in lines[start_idx:]:
        lower = line.lower()
        if any(lower == stop or lower.startswith(f"{stop} ") for stop in stop_l):
            break
        collected.append(line)
    return normalize_text(" ".join(collected))


def _extract_examples(section_text: str) -> list[str]:
    if not section_text:
        return []
    examples: list[str] = []
    matches = re.finditer(
        r"Example\s+\d+\s*(.*?)(?=(?:Example\s+\d+)|(?:Selected Observed Examples)|(?:Observed Examples)|(?:References)|\Z)",
        section_text,
        re.S | re.I,
    )
    for match in matches:
        text = normalize_text(match.group(1))
        if text:
            examples.append(text)
    if not examples:
        text = normalize_text(section_text)
        if text:
            examples.append(text)
    return examples


def _extract_title(lines: list[str], cwe: str) -> str:
    for line in lines[:50]:
        if cwe in line and ":" in line:
            return normalize_text(line.split(":", 1)[1])
    return ""


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _find_child(elem: ET.Element, name: str) -> ET.Element | None:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return child
    return None


def _find_children(elem: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in elem if _strip_ns(child.tag) == name]


def _flatten_elem_text(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    return normalize_text(" ".join(piece for piece in elem.itertext()))


def _load_xml_from_zip(zip_bytes: bytes) -> ET.Element:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        xml_name = next((name for name in zf.namelist() if name.lower().endswith(".xml")), None)
        if not xml_name:
            raise ValueError("MITRE ZIP did not contain an XML file")
        xml_bytes = zf.read(xml_name)
    return ET.fromstring(xml_bytes)


def parse_cwe_catalog_xml(xml_root: ET.Element) -> dict[str, Any]:
    catalog_attrs = {
        "catalog_name": xml_root.attrib.get("Name") or xml_root.attrib.get("Catalog_Name") or "",
        "catalog_version": xml_root.attrib.get("Version") or xml_root.attrib.get("Catalog_Version") or "",
        "catalog_date": xml_root.attrib.get("Date") or xml_root.attrib.get("Catalog_Date") or "",
    }

    entries: list[dict[str, Any]] = []
    seen_cwes: set[str] = set()
    for weakness in xml_root.iter():
        if _strip_ns(weakness.tag) != "Weakness":
            continue
        cwe_id = weakness.attrib.get("ID") or weakness.attrib.get("CWE_ID") or ""
        if not re.fullmatch(r"\d+", cwe_id or ""):
            continue
        cwe = f"CWE-{cwe_id}"
        if cwe in seen_cwes:
            continue
        seen_cwes.add(cwe)
        name = weakness.attrib.get("Name") or ""
        abstraction = weakness.attrib.get("Abstraction") or weakness.attrib.get("Weakness_Abstraction") or ""
        status = weakness.attrib.get("Status") or ""
        description = _flatten_elem_text(_find_child(weakness, "Description"))
        if not description:
            desc_elem = _find_child(weakness, "Description_Summary")
            description = _flatten_elem_text(desc_elem)
        extended_description = _flatten_elem_text(_find_child(weakness, "Extended_Description"))

        demonstrative_examples: list[str] = []
        demo_parent = _find_child(weakness, "Demonstrative_Examples")
        if demo_parent is not None:
            for demo in _find_children(demo_parent, "Demonstrative_Example"):
                text = _flatten_elem_text(demo)
                if text:
                    demonstrative_examples.append(text)

        observed_examples: list[str] = []
        observed_parent = _find_child(weakness, "Observed_Examples")
        if observed_parent is not None:
            for obs in _find_children(observed_parent, "Observed_Example"):
                text = _flatten_elem_text(obs)
                if text:
                    observed_examples.append(text)

        title = f"{cwe}: {name}".strip(": ")
        search_text = " ".join(
            [
                cwe,
                name,
                description,
                extended_description,
                " ".join(demonstrative_examples),
                " ".join(observed_examples),
            ]
        ).strip()
        entries.append(
            {
                "cwe": cwe,
                "name": name,
                "abstraction": abstraction,
                "status": status,
                "title": title,
                "description": description or LOCAL_CWE_NOTES.get(cwe, ""),
                "extended_description": extended_description,
                "demonstrative_examples": demonstrative_examples,
                "observed_examples": observed_examples,
                "url": cwe_url(cwe),
                "source": "mitre",
                "search_text": search_text,
                "search_tokens": tokenize_text(search_text),
            }
        )

    return {**catalog_attrs, "entries": entries}


def load_full_catalog_cache(cache_path: Path) -> dict[str, Any]:
    if not cache_path.exists():
        return {}
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def save_full_catalog_cache(cache_path: Path, catalog: dict[str, Any]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8")


def build_full_catalog_cache(
    cache_path: Path = DEFAULT_CWE_CATALOG_CACHE,
    refresh: bool = False,
) -> dict[str, Any]:
    if not refresh:
        cached = load_full_catalog_cache(cache_path)
        if cached.get("entries"):
            return cached

    zip_bytes = _fetch_bytes(MITRE_CWE_CATALOG_URL)
    root = _load_xml_from_zip(zip_bytes)
    catalog = parse_cwe_catalog_xml(root)
    save_full_catalog_cache(cache_path, catalog)
    return catalog


def score_catalog_entry(entry: dict[str, Any], query_tokens: list[str]) -> float:
    if not query_tokens:
        return 0.0

    entry_tokens = set(entry.get("search_tokens") or tokenize_text(entry.get("search_text", "")))
    if not entry_tokens:
        return 0.0

    title_tokens = set(tokenize_text(entry.get("title", "")))
    desc_tokens = set(tokenize_text(entry.get("description", "")))
    example_tokens = set(tokenize_text(" ".join(entry.get("demonstrative_examples") or [])))
    observed_tokens = set(tokenize_text(" ".join(entry.get("observed_examples") or [])))

    q = set(query_tokens)
    score = 0.0
    cwe_id = str(entry.get("cwe", "")).upper()
    cwe_num = cwe_id.split("-", 1)[1] if "-" in cwe_id else ""
    if cwe_id and cwe_id.lower() in {tok.lower() for tok in q}:
        score += 8.0
    if cwe_num and cwe_num in q:
        score += 4.0
    score += 4.0 * len(q & title_tokens)
    score += 2.0 * len(q & desc_tokens)
    score += 1.5 * len(q & example_tokens)
    score += 1.0 * len(q & observed_tokens)
    score += 0.25 * len(q & entry_tokens)
    return score


def search_full_catalog(
    catalog: dict[str, Any],
    query: str,
    top_k: int = 8,
    prefer_cwes: list[str] | None = None,
) -> list[dict[str, Any]]:
    entries = list(catalog.get("entries") or [])
    query_tokens = tokenize_text(query)
    preferred = set(split_cwe_values(prefer_cwes or []))
    scored: list[tuple[float, dict[str, Any]]] = []
    for entry in entries:
        score = score_catalog_entry(entry, query_tokens)
        if entry.get("cwe") in preferred:
            score += 10.0
        scored.append((score, entry))

    scored.sort(key=lambda item: (-item[0], item[1].get("cwe", "")))
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for score, entry in scored:
        cwe = str(entry.get("cwe", ""))
        if not cwe or cwe in seen:
            continue
        seen.add(cwe)
        result = {k: v for k, v in entry.items() if k not in {"search_tokens"}}
        result["score"] = round(score, 4)
        out.append(result)
        if len(out) >= top_k:
            break
    return out


def fetch_mitre_reference(cwe: str) -> dict[str, Any]:
    cwe = normalize_text(cwe)
    if not re.fullmatch(r"CWE-\d+", cwe, flags=re.I):
        raise ValueError(f"Invalid CWE id: {cwe}")

    url = cwe_url(cwe)
    html_text = _fetch_html(url)
    lines = _html_to_lines(html_text)
    description = _extract_section_lines(
        lines,
        "Description",
        {
            "Extended Description",
            "Demonstrative Examples",
            "Selected Observed Examples",
            "Observed Examples",
            "Common Consequences",
            "Potential Mitigations",
            "Applicable Platforms",
            "References",
            "Submissions",
            "Contributions",
            "Modifications",
            "Relationships",
            "Notes",
            "Content History",
            "Memberships",
            "Taxonomy Mappings",
            "Related Attack Patterns",
        },
    )
    examples_section = _extract_section_lines(
        lines,
        "Demonstrative Examples",
        {
            "Selected Observed Examples",
            "Observed Examples",
            "Common Consequences",
            "Potential Mitigations",
            "Applicable Platforms",
            "References",
            "Submissions",
            "Contributions",
            "Modifications",
            "Relationships",
            "Notes",
            "Content History",
            "Memberships",
            "Taxonomy Mappings",
            "Related Attack Patterns",
        },
    )
    observed_section = _extract_section_lines(
        lines,
        "Selected Observed Examples",
        {
            "Observed Examples",
            "Common Consequences",
            "Potential Mitigations",
            "Applicable Platforms",
            "References",
            "Submissions",
            "Contributions",
            "Modifications",
            "Relationships",
            "Notes",
            "Content History",
            "Memberships",
            "Taxonomy Mappings",
            "Related Attack Patterns",
        },
    )
    if not observed_section:
        observed_section = _extract_section_lines(
            lines,
            "Observed Examples",
            {
                "Common Consequences",
                "Potential Mitigations",
                "Applicable Platforms",
                "References",
                "Submissions",
                "Contributions",
                "Modifications",
                "Relationships",
                "Notes",
                "Content History",
                "Memberships",
                "Taxonomy Mappings",
                "Related Attack Patterns",
            },
        )

    title = _extract_title(lines, cwe)
    if not title:
        title = LOCAL_CWE_NOTES.get(cwe, "")

    return {
        "cwe": cwe,
        "url": url,
        "title": title,
        "description": description or LOCAL_CWE_NOTES.get(cwe, ""),
        "demonstrative_examples": _extract_examples(examples_section)[:3],
        "observed_examples": _extract_examples(observed_section)[:3],
        "source": "mitre" if description or examples_section or observed_section else "fallback",
    }


def load_reference_cache(cache_path: Path) -> dict[str, dict[str, Any]]:
    if not cache_path.exists():
        return {}
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def save_reference_cache(cache_path: Path, cache: dict[str, dict[str, Any]]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def build_reference_pack(
    cwe_values: list[str] | str,
    cache_path: Path | None = None,
    max_examples: int = 3,
    catalog_cache_path: Path = DEFAULT_CWE_CATALOG_CACHE,
    query_text: str = "",
    top_k: int = 8,
) -> dict[str, dict[str, Any]]:
    cwes = split_cwe_values(cwe_values)
    if not cwes and not query_text.strip():
        return {}

    catalog = build_full_catalog_cache(cache_path=catalog_cache_path)
    if not catalog.get("entries"):
        return {}

    query = " ".join([query_text, " ".join(cwes)]).strip()
    results = search_full_catalog(catalog, query, top_k=top_k, prefer_cwes=cwes)
    out: dict[str, dict[str, Any]] = {}
    for item in results:
        cwe = str(item.get("cwe", ""))
        if not cwe:
            continue
        out[cwe] = {
            "cwe": cwe,
            "url": item.get("url") or cwe_url(cwe),
            "title": item.get("title") or item.get("name") or cwe,
            "description": item.get("description") or "",
            "extended_description": item.get("extended_description") or "",
            "demonstrative_examples": list(item.get("demonstrative_examples") or [])[:max_examples],
            "observed_examples": list(item.get("observed_examples") or [])[:max_examples],
            "source": item.get("source") or "mitre",
            "score": item.get("score", 0.0),
        }
    return out
