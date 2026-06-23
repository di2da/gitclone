from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Sequence

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen import canvas

DEFAULT_TITLE = "Dance Kingdom Official Document"
BODY_FONT_SIZE = 12
TITLE_FONT_SIZE = 24
LINE_HEIGHT = 18
LEFT_MARGIN = 20 * mm
TOP_MARGIN = 25 * mm
BOTTOM_MARGIN = 20 * mm


def _get_font_name() -> str:
    """Use a built-in CJK font so Chinese text works on Vercel without bundling TTFs."""
    font_name = "STSong-Light"
    try:
        pdfmetrics.registerFont(UnicodeCIDFont(font_name))
    except Exception:
        pass
    return font_name


def build_pdf_bytes(
    content_list: Sequence[str],
    title: str = DEFAULT_TITLE,
) -> bytes:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    page_width, page_height = A4
    font_name = _get_font_name()

    pdf.setTitle(title)
    pdf.setAuthor("Dance Kingdom")
    pdf.setFont(font_name, TITLE_FONT_SIZE)
    pdf.drawCentredString(page_width / 2, page_height - TOP_MARGIN, title)

    pdf.setFont(font_name, BODY_FONT_SIZE)
    y_position = page_height - TOP_MARGIN - 28

    for line in content_list:
        if y_position < BOTTOM_MARGIN:
            pdf.showPage()
            pdf.setFont(font_name, BODY_FONT_SIZE)
            y_position = page_height - TOP_MARGIN
        pdf.drawString(LEFT_MARGIN, y_position, str(line))
        y_position -= LINE_HEIGHT

    pdf.save()
    return buffer.getvalue()


def generate_dk_document(
    filename: str | Path,
    content_list: Sequence[str],
    title: str = DEFAULT_TITLE,
) -> None:
    """Write a PDF file to disk."""
    Path(filename).write_bytes(build_pdf_bytes(content_list, title=title))


if __name__ == "__main__":
    test_content = [
        "這是一個專業文件測試 (Professional Test)",
        "解決問題 1: 亂碼 - 廣東話/中文顯示正常",
        "解決問題 2: 字體大小 - 參數化控制 fontSize",
        "Dance Kingdom Admin V10 Improved via Anti-Gravity",
    ]
    generate_dk_document("test_output.pdf", test_content)
