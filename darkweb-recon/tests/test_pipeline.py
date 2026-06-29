"""Unit tests for the analysis pipeline. Run: python -m pytest (or unittest)."""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Settings, Taxonomy
from app.db import Database
from app.extractors import extract
from app.matcher import analyze, analyze_many
from app.models import RawPost
from app.scraper import run_scan


class TestExtractors(unittest.TestCase):
    def test_crypto_and_contacts(self):
        text = (
            "Contact jabber: actor@exploit.im Telegram: @somehandle "
            "BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
            "ETH: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e "
            "ICQ: 728193044"
        )
        sel = extract(text)
        self.assertIn("jabber", sel)
        self.assertIn("telegram", sel)
        self.assertIn("btc", sel)
        self.assertIn("eth", sel)
        self.assertIn("icq", sel)
        self.assertEqual(sel["telegram"], ["somehandle"])

    def test_no_false_positive_on_clean_text(self):
        self.assertEqual(extract("just a normal sentence about cats"), {})


class TestMatcher(unittest.TestCase):
    def setUp(self):
        self.tax = Taxonomy.load()

    def test_high_signal_post_scores(self):
        post = RawPost(
            source="t", url="u", author="x", title="selling access",
            body="domain admin RDP access, ransomware affiliate. jabber: a@b.im",
        )
        a = analyze(post, self.tax)
        self.assertGreater(a.score, 0)
        self.assertIn("initial_access", a.categories)
        self.assertIn("ransomware", a.categories)

    def test_watchlist_flag(self):
        post = RawPost(
            source="t", url="u", author="x", title="re",
            body="looking for leaked db related to acme-corp.com",
        )
        a = analyze(post, self.tax)
        self.assertTrue(a.watchlist_hits)
        self.assertGreaterEqual(a.score, self.tax.watchlist_weight)

    def test_clean_post_filtered_out(self):
        clean = RawPost(source="t", url="u", author="x", title="hi",
                        body="hope you have a nice weekend")
        self.assertEqual(analyze_many([clean], self.tax), [])


class TestScanAndDB(unittest.TestCase):
    def test_demo_scan_end_to_end(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        settings = Settings.load()
        settings.demo_mode = True
        settings.database = tmp.name
        db = Database(tmp.name)
        summary = asyncio.run(run_scan(settings, Taxonomy.load(), db))
        self.assertEqual(summary["mode"], "demo")
        self.assertGreater(summary["matched"], 0)
        self.assertGreater(summary["new_findings"], 0)

        findings = db.findings()
        self.assertTrue(findings)
        # The benign "ghostwriter" post must not become a finding.
        self.assertNotIn("ghostwriter", [f["author"] for f in findings])

        actors = db.actors()
        self.assertTrue(any(a["author"] == "nullroute" for a in actors))

        # Re-running must not duplicate findings.
        summary2 = asyncio.run(run_scan(settings, Taxonomy.load(), db))
        self.assertEqual(summary2["new_findings"], 0)
        os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
