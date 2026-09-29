import inspect
import unittest

import docmagic_app


class CalendarInteractionTests(unittest.TestCase):
    def test_status_form_stops_click_from_opening_session_detail(self):
        source = inspect.getsource(docmagic_app._render_calendar_page)
        self.assertIn('onclick="event.stopPropagation()"', source)
        self.assertIn('onchange="this.form.submit()"', source)

    def test_month_total_excludes_adjacent_calendar_cells(self):
        source = inspect.getsource(docmagic_app._render_calendar_page)
        self.assertIn("current_month_session_count", source)
        self.assertIn("本月共 {current_month_session_count} 堂", source)


if __name__ == "__main__":
    unittest.main()
