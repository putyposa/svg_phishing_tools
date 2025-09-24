#!/usr/bin/env python3
import argparse
import os
import re
import sys
import unicodedata
from email import policy
from email.parser import BytesParser

SVG_REGEX = re.compile(r'(?is)<svg\b[^>]*>.*?</svg>')

def sanitize(name: str) -> str:
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if c.isalnum() or c in ("-", "_", "."))
    return name[:120] or "svg"

def decode_part(part) -> bytes:
    raw = part.get_payload(decode=True)
    if raw is None:
        payload = part.get_payload()
        if isinstance(payload, str):
            return payload.encode("utf-8", errors="replace")
        return b""
    return raw

def best_decode_text(b: bytes, charset_hint: str | None) -> str:
    encs = []
    if charset_hint:
        encs.append(charset_hint)
    encs += ["utf-8", "latin-1"]
    for enc in encs:
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="replace")

def save_bytes(base_dir: str, base_name: str, data: bytes, idx: int | None = None) -> str:
    if idx is None:
        fname = f"{sanitize(base_name)}.svg"
    else:
        fname = f"{sanitize(base_name)}_{idx:03d}.svg"
    out_path = os.path.join(base_dir, fname)
    counter = 1
    stem, ext = os.path.splitext(out_path)
    while os.path.exists(out_path):
        out_path = f"{stem}__{counter}{ext}"
        counter += 1
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path

def carve_inline_svgs(text_bytes: bytes, charset_hint: str | None, out_dir: str, label: str) -> list[str]:
    text = best_decode_text(text_bytes, charset_hint)
    paths = []
    for i, m in enumerate(SVG_REGEX.finditer(text), start=1):
        svg_str = m.group(0)
        svg_bytes = svg_str.replace("\r\n", "\n").encode("utf-8")
        path = save_bytes(out_dir, f"inline_{label}", svg_bytes, idx=i)
        paths.append(path)
    return paths

def process_eml(eml_path: str, out_dir: str) -> list[str]:
    with open(eml_path, "rb") as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    saved = []
    for part_idx, part in enumerate(msg.walk(), start=1):
        ctype = part.get_content_type()
        fname = part.get_filename()
        charset = part.get_content_charset()

        if ctype == "image/svg+xml" or (fname and fname.lower().endswith(".svg")):
            data = decode_part(part)
            base = fname[:-4] if (fname and fname.lower().endswith(".svg")) else (fname or f"attachment_{part_idx}")
            out = save_bytes(out_dir, base, data)
            saved.append(out)
            continue

        if ctype in ("text/html", "text/plain"):
            text_bytes = decode_part(part)
            label = f"{os.path.basename(eml_path)}_part{part_idx}_{ctype.replace('/', '-')}"
            inline_paths = carve_inline_svgs(text_bytes, charset, out_dir, label)
            saved.extend(inline_paths)

    if not saved:
        try:
            with open(eml_path, "rb") as fp:
                raw = fp.read()
            found = SVG_REGEX.findall(raw.decode("utf-8", errors="ignore"))
            for i, svg in enumerate(found, start=1):
                out = save_bytes(out_dir, f"{os.path.basename(eml_path)}_raw_source_inline", svg.encode("utf-8"), idx=i)
                saved.append(out)
        except Exception:
            pass
    return saved

def main():
    ap = argparse.ArgumentParser(description="Carve SVGs from .eml files (attachments and inline).")
    ap.add_argument("eml_path", help="Path to the .eml file OR a folder if --all is used")
    ap.add_argument("-o", "--out-dir", default="carved_svgs", help="Directory to write extracted SVGs")
    ap.add_argument("--all", action="store_true", help="Process every .eml file in the given folder")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    all_saved = []

    if args.all:
        if not os.path.isdir(args.eml_path):
            print(f"ERROR: {args.eml_path} is not a folder", file=sys.stderr)
            sys.exit(2)
        for fname in os.listdir(args.eml_path):
            if fname.lower().endswith(".eml"):
                eml_file = os.path.join(args.eml_path, fname)
                print(f"Processing {eml_file} ...")
                saved = process_eml(eml_file, args.out_dir)
                all_saved.extend(saved)
    else:
        if not os.path.isfile(args.eml_path):
            print(f"ERROR: {args.eml_path} is not a file", file=sys.stderr)
            sys.exit(2)
        all_saved = process_eml(args.eml_path, args.out_dir)

    if all_saved:
        print("Extracted SVGs:")
        for p in all_saved:
            print(" -", p)
        sys.exit(0)
    else:
        print("No SVGs found.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
