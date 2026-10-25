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

    def test_attendance_status_preserves_dropped_students(self):
        self.assertEqual(docmagic_app._attendance_normalize_status("dropped"), "dropped")
        self.assertEqual(docmagic_app._attendance_normalize_status("absent"), "absent")
        self.assertEqual(docmagic_app._attendance_normalize_status("present"), "present")
        self.assertEqual(docmagic_app._attendance_normalize_status("unexpected"), "present")

    def test_roster_submit_uses_shared_status_normalizer(self):
        source = inspect.getsource(docmagic_app.attendance_submit)
        self.assertIn("_attendance_normalize_status", source)
        self.assertNotIn('"absent" if status_value == "absent" else "present"', source)

    def test_absence_reason_options_are_restricted(self):
        options = docmagic_app._attendance_absence_reason_options_html()
        self.assertIn("未能聯絡", options)
        self.assertIn("病假/事假", options)
        self.assertEqual(docmagic_app._attendance_normalize_absence_reason("未能聯絡", "absent"), "未能聯絡")
        self.assertEqual(docmagic_app._attendance_normalize_absence_reason("病假/事假", "absent"), "病假/事假")
        self.assertEqual(docmagic_app._attendance_normalize_absence_reason("其他", "absent"), "")
        self.assertEqual(docmagic_app._attendance_normalize_absence_reason("未能聯絡", "present"), "")

    def test_roster_reason_is_a_dropdown(self):
        row = docmagic_app._attendance_roster_row_html((1, "學生", 1, ""))
        self.assertIn('<select class="roster-reason"', row)
        self.assertNotIn('<input class="roster-reason"', row)

    def test_attendance_page_script_has_no_optional_chain_assignment(self):
        source = inspect.getsource(docmagic_app._render_attendance_page)
        self.assertNotIn("?.textContent =", source)

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
