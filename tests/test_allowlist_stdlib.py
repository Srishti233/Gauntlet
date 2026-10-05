from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gauntlet.targets.allowlist import (
    DisallowedHostError,
    assert_host_allowed,
    is_host_allowed,
)


class TestHostAllowlist(unittest.TestCase):
    def test_localhost_allowed(self):
        self.assertTrue(is_host_allowed("http://localhost:8080/v1/chat/completions"))

    def test_127001_allowed(self):
        self.assertTrue(is_host_allowed("http://127.0.0.1:9100"))

    def test_ipv6_loopback_allowed(self):
        self.assertTrue(is_host_allowed("http://[::1]:8080"))

    def test_dot_localhost_allowed(self):
        self.assertTrue(is_host_allowed("http://aegis.localhost:8080"))

    def test_compose_service_name_allowed(self):
        self.assertTrue(is_host_allowed("http://aegis:8080/v1/chat/completions"))
        self.assertTrue(is_host_allowed("http://gullible-llm:9100"))

    def test_private_ip_allowed(self):
        self.assertTrue(is_host_allowed("http://10.0.0.5:8080"))
        self.assertTrue(is_host_allowed("http://192.168.1.5:8080"))

    def test_public_host_not_allowed(self):
        self.assertFalse(is_host_allowed("https://api.openai.com/v1/chat/completions"))
        self.assertFalse(is_host_allowed("https://some-random-saas.com/api"))

    def test_public_ip_not_allowed(self):
        self.assertFalse(is_host_allowed("http://8.8.8.8:80"))

    def test_assert_raises_on_disallowed_host(self):
        with self.assertRaises(DisallowedHostError):
            assert_host_allowed("https://evil.example.com/v1/chat/completions")

    def test_assert_does_not_raise_on_allowed_host(self):
        assert_host_allowed("http://localhost:8080")  # should not raise

    def test_override_allows_any_host(self):
        # should not raise with the explicit override
        assert_host_allowed(
            "https://some-random-saas.com/api", i_own_this_target=True
        )

    def test_extra_allowlist_entry(self):
        self.assertTrue(
            is_host_allowed(
                "https://my-own-staging-server.example.com",
                extra_allowlist={"my-own-staging-server.example.com"},
            )
        )

    def test_empty_host_not_allowed(self):
        self.assertFalse(is_host_allowed("not a url"))


if __name__ == "__main__":
    unittest.main()
