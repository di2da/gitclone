from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from pdf_engine import build_pdf_bytes

app = FastAPI(title="Dance Kingdom Admin V10", version="1.0.0")


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
    <!doctype html>
    <html lang="zh-Hant">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Dance Kingdom Admin V10</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Microsoft JhengHei", sans-serif;
            margin: 0;
            min-height: 100vh;
            background: linear-gradient(135deg, #f6f7fb 0%, #eef1f8 100%);
            color: #111827;
            display: grid;
            place-items: center;
          }
          .card {
            width: min(720px, calc(100vw - 32px));
            background: white;
            border: 1px solid #dbe2ef;
            border-radius: 20px;
            padding: 32px;
            box-shadow: 0 20px 50px rgba(15, 23, 42, 0.08);
          }
          h1 {
            margin: 0 0 12px;
            font-size: 32px;
          }
          p {
            margin: 8px 0;
            line-height: 1.6;
            font-size: 16px;
          }
          .actions {
            margin-top: 24px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
          }
          a {
            display: inline-block;
            padding: 12px 18px;
            border-radius: 999px;
            text-decoration: none;
            font-weight: 700;
          }
          .primary {
            background: #111827;
            color: white;
          }
          .secondary {
            background: #e5e7eb;
            color: #111827;
          }
          code {
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 6px;
          }
        </style>
      </head>
      <body>
        <main class="card">
          <h1>Dance Kingdom Admin V10</h1>
          <p>Professional PDF generation with Chinese font support is live.</p>
          <p>按下面按鈕可以下載測試 PDF，睇下字體大小同繁體中文顯示。</p>
          <div class="actions">
            <a class="primary" href="/api/pdf">Download PDF</a>
            <a class="secondary" href="/api/health">Health Check</a>
          </div>
          <p style="margin-top: 18px;">API: <code>/api/pdf</code></p>
        </main>
      </body>
    </html>
    """


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "dk-admin-v10"}


@app.get("/api/pdf")
def pdf() -> Response:
    content = [
        "這是一個專業文件測試 (Professional Test)",
        "解決問題 1: 亂碼 - 廣東話/中文顯示正常",
        "解決問題 2: 字體大小 - 標題 24pt，內文 12pt",
        "Dance Kingdom Admin V10 Improved via ReportLab",
    ]
    pdf_bytes = build_pdf_bytes(content, title="Dance Kingdom Admin V10")
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="dk-admin-test.pdf"'},
    )
