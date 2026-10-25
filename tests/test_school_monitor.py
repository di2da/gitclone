from datetime import date
import inspect
import unittest

import docmagic_app


class SchoolMonitorTests(unittest.TestCase):
    def test_past_default_session_counts_as_completed(self):
        today = date(2026, 10, 25)
        self.assertTrue(docmagic_app._school_session_is_effectively_completed("已排", "2026-10-24", today))
        self.assertTrue(docmagic_app._school_session_is_effectively_completed("已完成", "2026-11-01", today))

    def test_today_future_and_explicit_exceptions_do_not_auto_complete(self):
        today = date(2026, 10, 25)
        self.assertFalse(docmagic_app._school_session_is_effectively_completed("已排", "2026-10-25", today))
        self.assertFalse(docmagic_app._school_session_is_effectively_completed("已排", "2026-10-26", today))
        for status in ("取消", "取消待補", "改期", "待確認"):
            self.assertFalse(docmagic_app._school_session_is_effectively_completed(status, "2026-10-24", today))

    def test_monitor_displays_overall_and_program_progress(self):
        source = inspect.getsource(docmagic_app._render_school_monitor_page)
        self.assertIn("整體進度", source)
        self.assertIn("班別課堂進度", source)
        self.assertIn("已完成／總堂數", source)
        self.assertGreaterEqual(source.count("HAVING COUNT(DISTINCT ss.id) > 0"), 3)

    def test_monitor_prioritizes_management_focus_and_search(self):
        source = inspect.getsource(docmagic_app._render_school_monitor_page)
        self.assertIn("學校課堂營運總覽", source)
        self.assertIn("管理焦點", source)
        self.assertIn("本月關鍵數字", source)
        self.assertIn("data-open-tab", source)
        self.assertIn("monitor-search", source)
        self.assertIn("progress-track", source)


if __name__ == "__main__":
    unittest.main()
