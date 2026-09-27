import json
import unittest

from src.system_one import ForensicSystemOne


class ForensicSystemOneTests(unittest.TestCase):
    def test_off_mode_does_not_call_provider(self):
        def fail(*args):
            raise AssertionError("provider must not be called")

        client = ForensicSystemOne(
            mode="off",
            base_url="http://laya.test:8000",
            request_fn=fail,
        )
        self.assertIsNone(client.classify("failed login from unfamiliar source"))

    def test_advisory_mode_returns_typed_triage(self):
        def fake(url, body, headers, timeout):
            self.assertEqual(url, "http://laya.test:8000/v1/systemone")
            payload = json.loads(body.decode("utf-8"))
            self.assertTrue(
                payload["state"]["policy"]["deterministic_ioc_and_forensic_rules_remain_authoritative"]
            )
            return {
                "answers": {
                    "event_type": {
                        "type": "choice",
                        "choice": "authentication",
                        "confidence": 0.96,
                        "probabilities": {"authentication": 0.96, "other": 0.04},
                    },
                    "human_escalation": {
                        "type": "noul",
                        "noul": 0.83,
                        "confidence": 0.83,
                    },
                }
            }

        client = ForensicSystemOne(
            mode="advisory",
            base_url="http://laya.test:8000",
            request_fn=fake,
        )
        result = client.classify("Multiple failed logins followed by a successful login.")
        self.assertIsNotNone(result)
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["answers"]["event_type"]["choice"], "authentication")

    def test_failure_fails_open(self):
        def fail(*args):
            raise TimeoutError("down")

        client = ForensicSystemOne(
            mode="shadow",
            base_url="http://laya.test:8000",
            request_fn=fail,
        )
        self.assertIsNone(client.classify("suspicious process event"))


if __name__ == "__main__":
    unittest.main()
