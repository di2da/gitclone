import inspect
import unittest
from datetime import date

import docmagic_app


class AppleUxTests(unittest.TestCase):
    def test_human_date_labels(self):
        today = date(2026, 10, 1)
        self.assertEqual(docmagic_app._human_date_label(today, today), "今日")
        self.assertEqual(docmagic_app._human_date_label(date(2026, 10, 2), today), "聽日")
        self.assertEqual(docmagic_app._human_date_label(date(2026, 10, 3), today), "後日")

    def test_semantic_status_palette(self):
        self.assertEqual(docmagic_app._apple_status("已完成")[0], "#30D158")
        self.assertEqual(docmagic_app._apple_status("已排")[0], "#0A84FF")
        self.assertEqual(docmagic_app._apple_status("待確認")[0], "#FF9F0A")
        self.assertEqual(docmagic_app._apple_status("取消")[0], "#FF453A")

    def test_dashboard_keeps_today_first_structure(self):
        source = inspect.getsource(docmagic_app._render_class_control_page)
        self.assertLess(source.index('<div class="dashboard-head">'), source.index('<section class="cc-card today-focus">'))
        self.assertLess(source.index('<section class="cc-card today-focus">'), source.index("{reminder_html}"))
        self.assertIn("lesson-card", source)
        self.assertIn("tools-section", source)
        self.assertIn("tool-grid", source)

    def test_calendar_has_week_month_and_filters(self):
        source = inspect.getsource(docmagic_app._render_calendar_page)
        self.assertIn("week-grid", source)
        self.assertIn("month-grid", source)
        self.assertIn("segment", source)
        self.assertIn("✕ 清除篩選", source)
        self.assertIn("min-height:44px", source)
        self.assertIn("mobile-agenda", source)
        self.assertIn("filter-toggle", source)

    def test_login_uses_light_theme(self):
        html = docmagic_app._render_login_page()
        self.assertIn("--bg:#FAFAFA", html)
        self.assertIn("今日，由最重要嘅事開始。", html)


if __name__ == "__main__":
    unittest.main()
