#!/usr/bin/env python3
"""
Auto-translate PO entries where msgstr == msgid.

Scope:
- Updates singular entries with one-line msgid/msgstr blocks.
- Preserves existing non-empty translations.
- Uses Google Translate public endpoint for best-effort machine translations.

Usage:
  python build/auto-translate-untranslated.py
"""

from __future__ import annotations

import ast
import argparse
import pathlib
import re
import time
from typing import Dict, List, Tuple

import requests


ROOT = pathlib.Path(__file__).resolve().parents[1]
LANG_DIR = ROOT / "languages"
PO_GLOB = "nexifymy-security-*.po"
DEFAULT_BATCH_SIZE = 20
DEFAULT_SLEEP_SECONDS = 0.08
SEP_TOKEN = "[[NMSSEP_QX9]]"
NL_TOKEN = "[[NMSNL_QX9]]"


def po_unescape(value: str) -> str:
    return ast.literal_eval(f'"{value}"')


def po_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def locale_to_tl(locale: str) -> str:
    loc = locale.strip()
    if "_" in loc:
        base = loc.split("_", 1)[0].lower()
    else:
        base = loc.lower()

    # Normalize known variants.
    if loc in {"zh_CN", "zh_Hans"}:
        return "zh-CN"
    if loc in {"pt_BR"}:
        return "pt"
    if loc in {"tr_TR"}:
        return "tr"
    if loc in {"uk_UA"}:
        return "uk"
    if loc in {"vi_VN"}:
        return "vi"

    return base


def translate_batch(session: requests.Session, texts: List[str], tl: str) -> List[str]:
    encoded_texts = [text.replace("\n", NL_TOKEN) for text in texts]
    payload = SEP_TOKEN.join(encoded_texts)
    params = {
        "client": "gtx",
        "sl": "en",
        "tl": tl,
        "dt": "t",
        "q": payload,
    }
    resp = session.get(
        "https://translate.googleapis.com/translate_a/single",
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    translated = "".join(item[0] for item in data[0] if item and item[0] is not None)
    parts = translated.split(SEP_TOKEN)
    if len(parts) != len(texts):
        raise ValueError("Batch split mismatch")
    return [part.replace(NL_TOKEN, "\n") for part in parts]


def translate_single(session: requests.Session, text: str, tl: str) -> str:
    params = {
        "client": "gtx",
        "sl": "en",
        "tl": tl,
        "dt": "t",
        "q": text.replace("\n", NL_TOKEN),
    }
    resp = session.get(
        "https://translate.googleapis.com/translate_a/single",
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    translated = "".join(item[0] for item in data[0] if item and item[0] is not None)
    return translated.replace(NL_TOKEN, "\n")


def collect_untranslated_po_strings(content: str) -> List[str]:
    pattern = re.compile(
        r'^msgid "((?:\\.|[^"\\])*)"\r?\nmsgstr "((?:\\.|[^"\\])*)"$',
        re.MULTILINE,
    )
    entries: List[str] = []
    seen = set()

    for m in pattern.finditer(content):
        msgid_raw = m.group(1)
        msgstr_raw = m.group(2)
        if not msgid_raw:
            continue  # Header
        if msgid_raw != msgstr_raw:
            continue
        try:
            msgid_text = po_unescape(msgid_raw)
        except Exception:
            continue
        if msgid_text not in seen:
            seen.add(msgid_text)
            entries.append(msgid_text)
    return entries


def apply_translations_to_content(content: str, translations: Dict[str, str]) -> Tuple[str, int]:
    pattern = re.compile(
        r'(^msgid "((?:\\.|[^"\\])*)")(\r?\n)(msgstr "((?:\\.|[^"\\])*)"$)',
        re.MULTILINE,
    )
    replacements = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal replacements
        msgid_raw = match.group(2)
        msgstr_raw = match.group(5)
        newline = match.group(3)

        if not msgid_raw or msgid_raw != msgstr_raw:
            return match.group(0)

        try:
            msgid_text = po_unescape(msgid_raw)
        except Exception:
            return match.group(0)

        translated = translations.get(msgid_text)
        if not translated or translated == msgid_text:
            return match.group(0)

        replacements += 1
        return f'msgid "{msgid_raw}"{newline}msgstr "{po_escape(translated)}"'

    new_content = pattern.sub(repl, content)
    return new_content, replacements


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auto-translate PO entries where msgstr == msgid."
    )
    parser.add_argument(
        "--locale",
        action="append",
        default=[],
        help="Specific locale to process (repeatable), e.g. --locale ru_RU",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Translation request batch size (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=DEFAULT_SLEEP_SECONDS,
        help=f"Sleep seconds between requests (default: {DEFAULT_SLEEP_SECONDS})",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    po_files = sorted(LANG_DIR.glob(PO_GLOB))
    if not po_files:
        print("No PO files found.")
        return 1

    if args.locale:
        selected = set(args.locale)
        po_files = [
            p
            for p in po_files
            if p.stem.replace("nexifymy-security-", "") in selected
        ]
        if not po_files:
            print("No matching locale files found.")
            return 1

    batch_size = max(1, int(args.batch_size))
    sleep_seconds = max(0.0, float(args.sleep))

    session = requests.Session()
    session.trust_env = False  # bypass broken proxy env

    total_replaced = 0

    for po_path in po_files:
        locale = po_path.stem.replace("nexifymy-security-", "")
        tl = locale_to_tl(locale)

        content = po_path.read_text(encoding="utf-8", errors="replace")
        candidates = collect_untranslated_po_strings(content)
        if not candidates:
            print(f"{po_path.name}: no untranslated entries detected")
            continue

        translated_map: Dict[str, str] = {}
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i : i + batch_size]
            try:
                translated_batch = translate_batch(session, batch, tl)
            except Exception:
                translated_batch = []
                for src in batch:
                    try:
                        translated_batch.append(translate_single(session, src, tl))
                    except Exception:
                        translated_batch.append(src)

            for src, dst in zip(batch, translated_batch):
                translated_map[src] = dst.strip()

            time.sleep(sleep_seconds)

        updated_content, replaced = apply_translations_to_content(content, translated_map)
        if replaced > 0:
            po_path.write_text(updated_content, encoding="utf-8", newline="\n")

        total_replaced += replaced
        print(f"{po_path.name}: translated {replaced} entries (tl={tl})")

    print(f"Done. Total translated entries: {total_replaced}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
