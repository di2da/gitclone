import asyncio
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.requests import Request

import docmagic_app


class TeacherCreateTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "teachers.db"
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE teachers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                email TEXT DEFAULT '', data_consent TEXT DEFAULT '', english_name TEXT DEFAULT '',
                stage_name TEXT DEFAULT '', instagram TEXT DEFAULT '', phone TEXT DEFAULT '', area TEXT DEFAULT '',
                bank_name TEXT DEFAULT '', bank_account_number TEXT DEFAULT '', bank_holder_name TEXT DEFAULT '',
                fps_id TEXT DEFAULT '', dance_styles TEXT DEFAULT '', teaching_targets TEXT DEFAULT '',
                experience TEXT DEFAULT '', bio TEXT DEFAULT '', car_plate TEXT DEFAULT '',
                teaching_availability TEXT DEFAULT '', extra_work TEXT DEFAULT '', scnc_result TEXT DEFAULT '',
                remarks TEXT DEFAULT '', is_active INTEGER DEFAULT 1
            )
            """
        )
        conn.execute("INSERT INTO teachers (name) VALUES (?)", ("PO YIN",))
        conn.commit()
        conn.close()
        self.request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/salary/teachers/new",
                "headers": [],
                "query_string": b"",
                "server": ("test", 80),
                "client": ("test", 1),
                "scheme": "http",
            }
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_duplicate_teacher_returns_conflict_without_creating_another_row(self):
        with patch.object(docmagic_app, "DB_PATH", self.db_path), patch.object(
            docmagic_app, "_audit_action_request"
        ):
            response = asyncio.run(
                docmagic_app.salary_teacher_new_save(
                    request=self.request,
                    name=" PO YIN ",
                    email="",
                    data_consent=[],
                    english_name="",
                    stage_name="",
                    phone="",
                    area="",
                    bank_name="",
                    bank_account_number="",
                    bank_holder_name="",
                    fps_id="",
                    dance_styles=[],
                    teaching_targets=[],
                    experience="",
                    bio="",
                    car_plate="",
                    teaching_availability=[],
                    extra_work=[],
                    scnc_result="",
                    instagram="",
                    remarks="",
                    is_active="1",
                    user=(1, "admin", "Admin", "admin"),
                )
            )

        body = response.body.decode()
        self.assertEqual(response.status_code, 409)
        self.assertIn("系統已經有同名導師", body)
        self.assertNotIn("Traceback", body)
        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM teachers WHERE name='PO YIN'").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_production_error_page_does_not_expose_traceback_or_exception(self):
        self.request.state.request_id = "test-reference"
        with patch.object(docmagic_app, "_is_production", return_value=True):
            response = docmagic_app._internal_server_error_response(
                self.request, RuntimeError("sensitive database detail")
            )

        body = response.body.decode()
        self.assertEqual(response.status_code, 500)
        self.assertIn("test-reference", body)
        self.assertNotIn("Traceback", body)
        self.assertNotIn("sensitive database detail", body)


if __name__ == "__main__":
    unittest.main()
