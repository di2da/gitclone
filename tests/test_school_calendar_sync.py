import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import docmagic_app


class SchoolCalendarSyncTests(unittest.TestCase):
    def test_replaces_old_sheet_rows_and_keeps_cancelled_program_as_cancelled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "sync.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE schools (
                    id INTEGER PRIMARY KEY, school_year TEXT, name TEXT,
                    is_active INTEGER, created_at TEXT, updated_at TEXT
                );
                CREATE TABLE teachers (id INTEGER PRIMARY KEY, name TEXT, is_active INTEGER);
                CREATE TABLE school_programs (
                    id INTEGER PRIMARY KEY, school_id INTEGER, school_year TEXT, weekday TEXT,
                    program_name TEXT, default_start_time TEXT, default_end_time TEXT,
                    teacher_id INTEGER, teacher_name_snapshot TEXT, source_sheet_url TEXT,
                    source_row_key TEXT, source_raw_text TEXT, notes TEXT, is_active INTEGER,
                    created_at TEXT, updated_at TEXT
                );
                CREATE TABLE school_sessions (
                    id INTEGER PRIMARY KEY, program_id INTEGER, session_date TEXT,
                    start_time TEXT, end_time TEXT, session_type TEXT, status TEXT,
                    note TEXT, source_text TEXT, source_hash TEXT,
                    created_at TEXT, updated_at TEXT
                );
                INSERT INTO schools VALUES (1, '2026-27', '舊學校', 1, '', '');
                INSERT INTO school_programs VALUES (
                    1, 1, '2026-27', '星期一', '舊班', '', '', NULL, '',
                    'https://docs.google.com/spreadsheets/d/sheet123/edit', '', '', '', 1, '', ''
                );
                INSERT INTO school_sessions VALUES (
                    1, 1, '2026-09-01', '', '', '課堂', '已排', '', 'old', 'old', '', ''
                );
                """
            )
            preview = {
                "programs": [
                    {
                        "status": "review",
                        "source_row": 10,
                        "school_name": "新學校",
                        "school_raw": "新學校（取消）",
                        "program_name": "校隊",
                        "weekday": "星期一",
                        "start_time": "15:00",
                        "end_time": "16:00",
                        "teacher_names": ["Teacher"],
                        "schedule_text": "10月5日",
                        "warnings": ["需覆核"],
                        "events": [
                            {
                                "session_date": "2026-10-05",
                                "session_type": "課堂",
                                "source_text": "10月5日",
                            }
                        ],
                    }
                ]
            }
            with patch.object(docmagic_app, "SCHOOL_SYNC_MIN_PROGRAMS", 1), patch.object(
                docmagic_app, "SCHOOL_SYNC_MIN_SESSIONS", 1
            ):
                result = docmagic_app._write_school_calendar_preview(
                    conn,
                    preview,
                    school_year="2026-27",
                    source_sheet_url="https://docs.google.com/spreadsheets/d/sheet123/edit",
                    replace_existing=True,
                )
            conn.commit()
            self.assertEqual(result["removed_sessions"], 1)
            self.assertEqual(result["sessions"], 1)
            self.assertEqual(conn.execute("SELECT status FROM school_sessions").fetchone()[0], "取消")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM school_programs").fetchone()[0], 1)
            conn.close()


if __name__ == "__main__":
    unittest.main()
