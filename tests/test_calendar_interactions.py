import inspect
import unittest

import docmagic_app


class CalendarInteractionTests(unittest.TestCase):
    def test_status_form_stops_click_from_opening_session_detail(self):
        source = inspect.getsource(docmagic_app._render_calendar_page)
        self.assertIn('onclick="event.stopPropagation()"', source)
        self.assertIn('onchange="this.form.submit()"', source)


if __name__ == "__main__":
    unittest.main()
