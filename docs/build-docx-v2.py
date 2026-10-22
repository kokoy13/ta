from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "draf-proposal-bab1-3-v2.md"
TARGET = ROOT / "Draf-Proposal-BabI-III-v2.docx"
REFERENCE = ROOT / "Draf-Proposal-BabI-III.docx"
TITLE = (
    "Pengembangan dan Implementasi Security Operations Center Berbasis Log "
    "untuk Analisis Keamanan Open Journal Systems Menggunakan MCP Server dan "
    "AI Agent dengan Metode Behavior-Based Detection"
)
EXTRA_STYLES = (
    '<w:style w:type="paragraph" w:styleId="Compact">'
    '<w:name w:val="Compact"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="Compact"/><w:qFormat/>'
    '<w:pPr><w:spacing w:before="0" w:after="0" w:line="240" '
    'w:lineRule="auto"/></w:pPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="FirstParagraph">'
    '<w:name w:val="First Paragraph"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="BodyText"/><w:qFormat/></w:style>'
    '<w:style w:type="paragraph" w:styleId="BlockText">'
    '<w:name w:val="Block Text"/><w:basedOn w:val="Normal"/><w:qFormat/>'
    '<w:pPr><w:ind w:left="720" w:right="720"/>'
    '<w:spacing w:before="120" w:after="120" w:line="240" '
    'w:lineRule="auto"/></w:pPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="CoverTitle">'
    '<w:name w:val="CoverTitle"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="CoverSubtitle"/><w:qFormat/>'
    '<w:pPr><w:jc w:val="center"/>'
    '<w:spacing w:before="0" w:after="360"/></w:pPr>'
    '<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
    '<w:b/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="CoverSubtitle">'
    '<w:name w:val="CoverSubtitle"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="CoverText"/><w:qFormat/>'
    '<w:pPr><w:jc w:val="center"/>'
    '<w:spacing w:before="0" w:after="480"/></w:pPr>'
    '<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
    '<w:b/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="CoverText">'
    '<w:name w:val="CoverText"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="CoverText"/><w:qFormat/>'
    '<w:pPr><w:jc w:val="center"/>'
    '<w:spacing w:before="0" w:after="120"/></w:pPr>'
    '<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
    '<w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>'
)


def find_pandoc() -> str:
    found = shutil.which("pandoc")
    if found:
        return found
    candidates = [
        Path.home() / "AppData" / "Local" / "Pandoc" / "pandoc.exe",
        Path("/usr/bin/pandoc"),
        Path("/usr/local/bin/pandoc"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError("pandoc tidak ditemukan")


def add_page_breaks(text: str) -> str:
    targets = ("IDENTITAS", "ABSTRAK", "BAB I ", "BAB II ", "BAB III ", "DAFTAR PUSTAKA")

    def repl(match: re.Match[str]) -> str:
        block = match.group(0)
        if 'w:pStyle w:val="Heading2"' not in block:
            return block
        content = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", block, re.S)).strip()
        if not content.startswith(targets):
            return block
        if "<w:pageBreakBefore/>" in block:
            return block
        if "<w:pPr>" in block:
            return block.replace("<w:pPr>", "<w:pPr><w:pageBreakBefore/>", 1)
        return re.sub(
            r"(<w:p\b[^>]*>)",
            r"\1<w:pPr><w:pageBreakBefore/></w:pPr>",
            block,
            count=1,
        )

    return re.sub(r"<w:p\b[^>]*>.*?</w:p>", repl, text, flags=re.S)


def postprocess(path: Path) -> None:
    tmp = path.with_suffix(".tmp.docx")
    with zipfile.ZipFile(path, "r") as src, zipfile.ZipFile(
        tmp, "w", zipfile.ZIP_DEFLATED
    ) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "word/document.xml":
                text = data.decode("utf-8")
                text = re.sub(
                    r'(<w:tblStyle w:val=")Table(")',
                    r"\1TableGrid\2",
                    text,
                )
                text = add_page_breaks(text)
                data = text.encode("utf-8")
            elif item.filename == "word/styles.xml":
                text = data.decode("utf-8")
                if 'w:styleId="Compact"' not in text:
                    text = text.replace("</w:styles>", EXTRA_STYLES + "</w:styles>")
                data = text.encode("utf-8")
            elif item.filename == "docProps/core.xml":
                text = data.decode("utf-8")
                text = re.sub(
                    r"<dc:title(?:/>|>.*?</dc:title>)",
                    f"<dc:title>{TITLE}</dc:title>",
                    text,
                    count=1,
                )
                data = text.encode("utf-8")
            dst.writestr(item, data)
    shutil.move(tmp, path)


def verify(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
        styles = archive.read("word/styles.xml").decode("utf-8")
        core = archive.read("docProps/core.xml").decode("utf-8")
    if TITLE not in core:
        raise RuntimeError("metadata judul belum diperbarui")
    used = set(re.findall(r'<w:pStyle w:val="([^"]+)"', document))
    missing = sorted(style for style in used if f'w:styleId="{style}"' not in styles)
    if missing:
        raise RuntimeError(f"style tidak terdefinisi: {missing}")
    if '<w:tblStyle w:val="Table"/>' in document:
        raise RuntimeError("table style Table belum diganti")
    if document.count("<w:tbl>") != 9:
        raise RuntimeError("jumlah tabel tidak sesuai (harus 9)")
    if document.count("<w:pageBreakBefore/>") != 6:
        raise RuntimeError("jumlah page break tidak sesuai (harus 6)")


def main() -> None:
    pandoc = find_pandoc()
    subprocess.run(
        [
            pandoc,
            str(SOURCE),
            "-o",
            str(TARGET),
            "--from=gfm+fenced_divs",
            f"--reference-doc={REFERENCE}",
        ],
        check=True,
    )
    postprocess(TARGET)
    verify(TARGET)
    print(f"OK {TARGET} ({TARGET.stat().st_size} bytes)")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"GAGAL: {exc}", file=sys.stderr)
        raise SystemExit(1)
