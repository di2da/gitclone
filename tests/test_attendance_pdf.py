import inspect
import io
import unittest

from pypdf import PdfReader

import docmagic_app


class AttendancePdfTests(unittest.TestCase):
    @staticmethod
    def _sheet(number, student_count):
        statuses = ["present", "absent", "dropped", ""]
        lesson_dates = ["2026-10-25", "2026-11-01", "2026-11-08", "2026-11-15", "2026-11-22"]
        students = []
        for index in range(1, student_count + 1):
            status = statuses[(index - 1) % len(statuses)]
            students.append({
                "name": f"測試學生 {number}-{index}",
                "class_name": "K2",
                "school_name": "元朗示範幼稚園",
                "attendance": {
                    lesson_date: {
                        "status": status if lesson_date == "2026-10-25" else "",
                        "reason": "未能聯絡" if lesson_date == "2026-10-25" and status == "absent" else "",
                    }
                    for lesson_date in lesson_dates
                },
            })
        return {
            "title": f"第 {number} 節-{chr(67 + number)}｜2026-2027 第一期幼兒 KPOP 舞動全城計劃",
            "time": f"{8 + number:02d}:00–{8 + number:02d}:50",
            "weekday": "星期日",
            "category": "KPOP",
            "teachers": "Sammi, Ruby",
            "venue": "一樓禮堂",
            "dates": lesson_dates,
            "students": students,
        }

    def test_four_classes_export_as_four_page_landscape_pdf(self):
        sheets = [self._sheet(1, 29), self._sheet(2, 28), self._sheet(3, 30), self._sheet(4, 31)]
        pdf_bytes = docmagic_app._build_attendance_daily_pdf("元朗", "2026-10-25", sheets)

        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        reader = PdfReader(io.BytesIO(pdf_bytes))
        self.assertEqual(len(reader.pages), 4)
        self.assertGreater(float(reader.pages[0].mediabox.width), float(reader.pages[0].mediabox.height))
        extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
        self.assertIn("活動資料", extracted)
        self.assertIn("上課日期", extracted)
        self.assertIn("班別", extracted)
        self.assertIn("元朗", extracted)
        self.assertIn("第 4 節", extracted)
        self.assertIn("測試學生 4-31", extracted)
        self.assertIn("未能聯絡", extracted)
        self.assertIn("已退學", extracted)
        self.assertIn("元朗示範幼稚園", extracted)
        self.assertIn("25/10", extracted)
        self.assertIn("22/11", extracted)

    def test_student_metadata_round_trip_and_structured_line(self):
        note = docmagic_app._attendance_student_note("K3", "元朗示範幼稚園")
        self.assertEqual(
            docmagic_app._attendance_student_metadata(note),
            {"class_name": "K3", "school_name": "元朗示範幼稚園"},
        )
        self.assertEqual(
            docmagic_app._attendance_parse_student_line("K3 | 陳小明 | 元朗示範幼稚園"),
            ("陳小明", "K3", "元朗示範幼稚園"),
        )
        self.assertEqual(
            docmagic_app._attendance_student_line("陳小明", note),
            "K3 | 陳小明 | 元朗示範幼稚園",
        )

    def test_pdf_font_covers_traditional_and_simplified_student_names(self):
        font_name = docmagic_app._attendance_pdf_font_name()
        face = docmagic_app.pdfmetrics.getFont(font_name).face
        for character in "張张銳锐許梓晞":
            self.assertTrue(face.charToGlyph.get(ord(character), 0), character)

    def test_attendance_page_contains_daily_pdf_button(self):
        source = inspect.getsource(docmagic_app._render_attendance_page)
        self.assertIn("本日點名紙導出", source)
        self.assertIn("/attendance/daily.pdf", source)

    def test_daily_pdf_route_requires_area_and_uses_hk_today_default(self):
        source = inspect.getsource(docmagic_app.attendance_daily_pdf)
        self.assertIn("請先選擇有效地區", source)
        self.assertIn("_hk_today().isoformat()", source)
        self.assertIn("Cache-Control", source)


if __name__ == "__main__":
    unittest.main()
