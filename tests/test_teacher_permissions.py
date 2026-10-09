import inspect
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

import docmagic_app


class TeacherPermissionTests(unittest.TestCase):
    def setUp(self):
        self.request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/salary/teachers",
                "headers": [],
                "query_string": b"",
                "server": ("test", 80),
                "client": ("test", 1),
                "scheme": "http",
            }
        )

    def test_all_teacher_data_routes_are_admin_only(self):
        endpoints = [
            docmagic_app.salary_teachers,
            docmagic_app.salary_teacher_new,
            docmagic_app.salary_teacher_new_save,
            docmagic_app.salary_teacher_edit,
            docmagic_app.salary_teacher_edit_save,
            docmagic_app.salary_teacher_detail,
        ]
        finance = (2, "finance", "Finance", "finance")
        admin = (1, "admin", "Admin", "admin")
        for endpoint in endpoints:
            dependency = inspect.signature(endpoint).parameters["user"].default.dependency
            with self.subTest(endpoint=endpoint.__name__), patch.object(
                docmagic_app, "_current_user_record", return_value=finance
            ):
                with self.assertRaises(HTTPException) as denied:
                    dependency(self.request, credentials=None)
                self.assertEqual(denied.exception.status_code, 403)
            with self.subTest(endpoint=endpoint.__name__), patch.object(
                docmagic_app, "_current_user_record", return_value=admin
            ):
                self.assertEqual(dependency(self.request, credentials=None), admin)

    def test_teacher_navigation_is_hidden_from_finance(self):
        finance_page = docmagic_app.render_salary_page("測試", "內容", user=(2, "finance", "Finance", "finance"))
        admin_page = docmagic_app.render_salary_page("測試", "內容", user=(1, "admin", "Admin", "admin"))
        self.assertNotIn('href="/salary/teachers"', finance_page.body.decode())
        self.assertIn('href="/salary/teachers"', admin_page.body.decode())

    def test_teacher_form_uses_the_matching_create_and_edit_routes(self):
        create_form = docmagic_app._teacher_form_html(self.request)
        edit_teacher = (42, "測試導師")
        edit_form = docmagic_app._teacher_form_html(self.request, edit_teacher)

        self.assertIn('action="/salary/teachers/new"', create_form)
        self.assertNotIn('action="/salary/teacher//edit"', create_form)
        self.assertIn('action="/salary/teacher/42/edit"', edit_form)


if __name__ == "__main__":
    unittest.main()
