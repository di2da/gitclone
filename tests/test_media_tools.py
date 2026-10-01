import inspect
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.requests import Request

import docmagic_app


class MediaToolsTests(unittest.TestCase):
    def setUp(self):
        self.request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/media-tools",
                "headers": [],
                "query_string": b"",
                "server": ("test", 80),
                "client": ("test", 1),
                "scheme": "https",
            }
        )

    def test_phone_normalization(self):
        self.assertEqual(docmagic_app._normalize_delivery_phone("6700 4444"), "+85267004444")
        self.assertEqual(docmagic_app._normalize_delivery_phone("00852-6700-4444"), "+85267004444")
        self.assertEqual(docmagic_app._normalize_delivery_phone("bad-number"), "")

    def test_media_url_rejects_local_targets(self):
        self.assertEqual(docmagic_app._safe_media_url("http://localhost/a"), "")
        self.assertEqual(docmagic_app._safe_media_url("http://127.0.0.1/a"), "")
        self.assertEqual(docmagic_app._safe_media_url("file:///tmp/a"), "")
        self.assertEqual(
            docmagic_app._safe_media_url("https://www.youtube.com/watch?v=abc"),
            "https://www.youtube.com/watch?v=abc",
        )

    def test_tutor_can_use_media_tools(self):
        dependency = inspect.signature(docmagic_app.media_tools_page).parameters["user"].default.dependency
        tutor = (2, "tutor", "Tutor", "tutor")
        with patch.object(docmagic_app, "_current_user_record", return_value=tutor):
            self.assertEqual(dependency(self.request, credentials=None), tutor)

    def test_worker_uses_omniget_engine_and_private_whatsapp(self):
        source = (Path(__file__).parents[1] / "scripts" / "media_worker.py").read_text(encoding="utf-8")
        self.assertIn("wtf.tonho.omniget", source)
        self.assertIn('"--channel",\n            "whatsapp"', source)
        self.assertIn('"--force-document"', source)
        self.assertIn("_ensure_public_host", source)
        self.assertIn('"media-worker-tmp"', source)
        self.assertIn('dir=str(WORK_ROOT)', source)

    def test_worker_api_has_separate_bearer_gate(self):
        source = inspect.getsource(docmagic_app._security_gate_middleware)
        self.assertIn('request.url.path.startswith("/api/media/jobs/")', source)
        self.assertIn("_media_worker_authorized", source)

    def test_failed_jobs_can_be_retried_without_resubmitting_url(self):
        page_source = inspect.getsource(docmagic_app._render_media_tools_page)
        route_source = inspect.getsource(docmagic_app.media_tools_retry_job)
        self.assertIn("重新處理", page_source)
        self.assertIn("requested_by=?", route_source)
        self.assertIn("status='failed'", route_source)


if __name__ == "__main__":
    unittest.main()
