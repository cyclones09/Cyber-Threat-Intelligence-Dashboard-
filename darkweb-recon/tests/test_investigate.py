"""Tests for the investigate pipeline, LLM degradation, and exports."""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import llm, maltego
from app.config import Settings, Taxonomy
from app.db import Database
from app.discovery import _extract_onion, discover
from app.investigate import investigate
from app.osint import enrich_spiderfoot, enrich_virustotal


class TestLLMDegradation(unittest.TestCase):
    """With no API key, every LLM function must fall back deterministically."""

    def setUp(self):
        self._saved = os.environ.pop("ANTHROPIC_API_KEY", None)

    def tearDown(self):
        if self._saved is not None:
            os.environ["ANTHROPIC_API_KEY"] = self._saved

    def test_unavailable(self):
        self.assertFalse(llm.available())

    def test_refine_fallback(self):
        r = llm.refine_query("Acme Corp")
        self.assertIn("Acme Corp", r.queries)
        self.assertTrue(any("leak" in q for q in r.queries))

    def test_filter_fallback_keeps_scored(self):
        cands = [{"title": "a", "snippet": "x", "score": 10},
                 {"title": "b", "snippet": "y", "score": 0}]
        self.assertEqual(llm.filter_results("obj", cands), [0])

    def test_summary_fallback(self):
        s = llm.generate_summary("Acme", [{"confidence": "high",
                                           "watchlist_hits": ["acme"]}], [])
        self.assertIn("Acme", s)


class TestDiscovery(unittest.TestCase):
    def test_extract_onion_plain(self):
        self.assertEqual(
            _extract_onion("http://abc.onion/x"), "http://abc.onion/x")

    def test_extract_onion_redirect(self):
        href = "/search/redirect?redirect_url=http://xyz.onion/page"
        self.assertEqual(_extract_onion(href), "http://xyz.onion/page")

    def test_extract_onion_none(self):
        self.assertIsNone(_extract_onion("https://example.com"))

    def test_demo_discover(self):
        s = Settings.load(); s.demo_mode = True
        results = asyncio.run(discover(s, ["acme"]))
        self.assertTrue(results)
        self.assertTrue(all(".onion" in d.url for d in results))


class TestInvestigateDemo(unittest.TestCase):
    def test_end_to_end_demo_no_enrich(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        os.environ.pop("ANTHROPIC_API_KEY", None)
        s = Settings.load(); s.demo_mode = True; s.database = tmp.name
        db = Database(tmp.name)
        result = asyncio.run(
            investigate("acme-corp.com", s, Taxonomy.load(), db, enrich=False))
        self.assertGreater(result["discovered"], 0)
        self.assertGreater(result["matched"], 0)
        self.assertFalse(result["llm_enabled"])
        self.assertIn("acme-corp.com", result["objective"])
        # Investigation was persisted.
        self.assertTrue(db.investigations())
        os.unlink(tmp.name)


class TestSpiderFoot(unittest.TestCase):
    def test_skips_without_url(self):
        saved = os.environ.pop("SPIDERFOOT_URL", None)
        try:
            r = asyncio.run(enrich_spiderfoot("acme-corp.com"))
            self.assertFalse(r.ok)
            self.assertIn("SPIDERFOOT_URL", r.note)
            self.assertEqual(r.connector, "spiderfoot")
            self.assertEqual(r.selector_type, "domain")
        finally:
            if saved is not None:
                os.environ["SPIDERFOOT_URL"] = saved

    def test_target_type_detection(self):
        from app.osint.spiderfoot import _guess_type
        self.assertEqual(_guess_type("1.2.3.4"), "ip")
        self.assertEqual(_guess_type("a@b.com"), "email")
        self.assertEqual(_guess_type("acme.com"), "domain")
        self.assertEqual(_guess_type("Jane Doe"), "username/name")


class TestVirusTotal(unittest.TestCase):
    def test_skips_without_key(self):
        saved = os.environ.pop("VIRUSTOTAL_API_KEY", None)
        try:
            r = asyncio.run(enrich_virustotal("acme-corp.com"))
            self.assertFalse(r.ok)
            self.assertIn("VIRUSTOTAL_API_KEY", r.note)
            self.assertEqual(r.connector, "virustotal")
        finally:
            if saved is not None:
                os.environ["VIRUSTOTAL_API_KEY"] = saved

    def test_indicator_type_detection(self):
        from app.osint.virustotal import _endpoint
        self.assertEqual(_endpoint("1.2.3.4")[1], "ip")
        self.assertEqual(_endpoint("acme.com")[1], "domain")
        self.assertEqual(_endpoint("a" * 64)[1], "hash")


class TestMaltegoExport(unittest.TestCase):
    def test_csv_and_graph(self):
        actors = [{
            "author": "nullroute", "posts": 2, "max_score": 17,
            "total_score": 30, "sources": ["demo"],
            "categories": {"initial_access": 2},
            "selectors": {"jabber": ["nullroute@exploit.im"],
                          "btc": ["bc1qexample"]},
        }]
        csv_out = maltego.to_csv(actors)
        self.assertIn("Source,SourceType,Target,TargetType,Edge", csv_out)
        self.assertIn("nullroute", csv_out)
        self.assertIn("uses_jabber", csv_out)

        import json
        graph = json.loads(maltego.to_graph_json(actors))
        self.assertTrue(graph["nodes"])
        self.assertTrue(graph["edges"])


if __name__ == "__main__":
    unittest.main()
