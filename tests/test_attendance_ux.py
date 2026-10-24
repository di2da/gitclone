import inspect
import unittest

import docmagic_app


class AttendanceUxTests(unittest.TestCase):
    def test_lesson_dates_are_extracted_and_deduplicated(self):
        notes = "上課日期：2026-10-25、2026-11-01、2026-10-25；錯誤：2026-13-40"
        self.assertEqual(
            docmagic_app._attendance_lesson_dates(notes),
            ["2026-10-25", "2026-11-01"],
        )

    def test_fixed_lesson_dates_render_as_select(self):
        control = docmagic_app._attendance_class_date_control(
            "上課日期：2026-10-25、2026-11-01", "2026-10-25"
        )
        self.assertIn('<select name="class_date"', control)
        self.assertIn('value="2026-10-25" selected', control)
        self.assertNotIn('type="date"', control)

    def test_legacy_lessons_keep_date_input(self):
        control = docmagic_app._attendance_class_date_control("沒有指定日期", "2026-10-25")
        self.assertIn('type="date"', control)

    def test_attendance_page_uses_distinct_colored_zones(self):
        source = inspect.getsource(docmagic_app._render_attendance_page)
        self.assertIn("flow-zone", source)
        self.assertIn("lesson-zone", source)
        self.assertIn("student-zone", source)
        self.assertNotIn("示範案例 1", source)
        self.assertNotIn("lesson-card-note", inspect.getsource(docmagic_app._attendance_lesson_group_cards_html))
        self.assertIn("請選擇這個課堂的指定上課日期", inspect.getsource(docmagic_app.attendance_submit))


if __name__ == "__main__":
    unittest.main()
