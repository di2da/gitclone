import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.requests import Request

import docmagic_app


class SessionDetailTests(unittest.TestCase):
    def test_detail_uses_school_contacts_table(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "detail.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE schools (id INTEGER PRIMARY KEY, name TEXT);
                CREATE TABLE teachers (id INTEGER PRIMARY KEY, name TEXT, phone TEXT, email TEXT);
                CREATE TABLE school_programs (
                    id INTEGER PRIMARY KEY, school_id INTEGER, program_name TEXT, weekday TEXT,
                    default_start_time TEXT, default_end_time TEXT, teacher_id INTEGER,
                    teacher_name_snapshot TEXT
                );
                CREATE TABLE school_sessions (
                    id INTEGER PRIMARY KEY, program_id INTEGER, session_date TEXT, start_time TEXT,
                    end_time TEXT, session_type TEXT, status TEXT, note TEXT,
                    created_at TEXT, updated_at TEXT
                );
                CREATE TABLE school_contacts (
                    id INTEGER PRIMARY KEY, school_id INTEGER, name TEXT, phone TEXT,
                    whatsapp TEXT, email TEXT, is_primary INTEGER, sort_order INTEGER,
                    is_active INTEGER
                );
                INSERT INTO schools VALUES (1, '測試學校');
                INSERT INTO teachers VALUES (1, '測試導師', '', '');
                INSERT INTO school_programs VALUES (1, 1, '舞蹈班', '星期三', '15:00', '16:00', 1, '');
                INSERT INTO school_sessions VALUES (1, 1, '2026-09-30', '15:00', '16:00', '課堂', '已排', '', '2026-09-01', '2026-09-01');
                INSERT INTO school_contacts VALUES (1, 1, '陳老師', '21234567', '', '', 1, 0, 1);
                """
            )
            conn.commit()
            conn.close()
            request = Request(
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/calendar/session/1",
                    "headers": [],
                    "query_string": b"",
                    "server": ("test", 80),
                    "client": ("test", 1),
                    "scheme": "http",
                }
            )
            with patch.object(docmagic_app, "DB_PATH", db_path):
                page = docmagic_app._render_session_detail_page(request, 1)
            self.assertIn("測試學校", page)
            self.assertIn("陳老師", page)
            self.assertIn("21234567", page)


if __name__ == "__main__":
    unittest.main()
