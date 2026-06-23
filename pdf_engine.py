import os
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import A4

def generate_dk_document(filename, content_list, title="Dance Kingdom Official Document"):
    """
    Professional PDF Generator for Dance Kingdom.
    Solves: 1. Chinese character Mojibake (亂碼) 2. Font sizing issues.
    """
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    # 1. Register Chinese Font (Ensure the font file exists on the server)
    # For local development on iMac Pro, we use system fonts or bundled fonts.
    try:
        # Example path - in production, bundle the .ttf file in the repo
        font_path = "/System/Library/Fonts/Supplemental/Arial Unicode.ttf" 
        pdfmetrics.registerFont(TTFont('ChineseFont', font_path))
        main_font = 'ChineseFont'
    except:
        main_font = 'Helvetica' # Fallback

    # 2. Set Header
    c.setFont(main_font, 24)
    c.drawCentredString(width / 2, height - 50, title)

    # 3. Dynamic Content with proper sizing
    y_position = height - 100
    c.setFont(main_font, 12) # Base font size
    
    for line in content_list:
        if y_position < 50: # Simple pagination
            c.showPage()
            c.setFont(main_font, 12)
            y_position = height - 50
            
        c.drawString(50, y_position, line)
        y_position -= 20

    c.save()

if __name__ == "__main__":
    test_content = [
        "這是一個專業文件測試 (Professional Test)",
        "解決問題 1: 亂碼 - 廣東話/中文顯示正常",
        "解決問題 2: 字體大小 - 參數化控制 fontSize",
        "Dance Kingdom Admin V10 Improved via Anti-Gravity"
    ]
    generate_dk_document("test_output.pdf", test_content)
