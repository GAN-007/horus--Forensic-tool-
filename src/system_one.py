"""Advisory Laya/Jev-compatible triage for forensic investigation evidence.

This module does not collect evidence or execute security actions. Horus modules
and deterministic forensic/IOC rules remain authoritative.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable

RequestFn = Callable[[str, bytes, dict[str, str], float], dict[str, Any]]


class ForensicSystemOne:
    VALID_MODES = {"off", "shadow", "advisory"}

    def __init__(
        self,
        *,
        mode: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float | None = None,
        request_fn: RequestFn | None = None,
    ) -> None:
        configured_mode = (mode or os.getenv("HORUS_SYSTEM_ONE_MODE", "off")).strip().lower()
        self.mode = configured_mode if configured_mode in self.VALID_MODES else "off"
        self.base_url = (
            base_url if base_url is not None else os.getenv("HORUS_SYSTEM_ONE_BASE_URL", "")
        ).rstrip("/")
        self.api_key = (
            api_key if api_key is not None else os.getenv("HORUS_SYSTEM_ONE_API_KEY", "")
        ).strip()
        self.timeout_seconds = max(
            0.1,
            float(
                timeout_seconds
                if timeout_seconds is not None
                else os.getenv("HORUS_SYSTEM_ONE_TIMEOUT_SECONDS", "1.5")
            ),
        )
        self._request_fn = request_fn or self._post_json

    @property
    def enabled(self) -> bool:
        return self.mode != "off" and bool(self.base_url)

    @staticmethod
    def _post_json(
        url: str,
        body: bytes,
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("System-One response must be a JSON object")
        return payload

    def classify(
        self,
        evidence: str,
        *,
        source: str = "manual",
        case_id: str | None = None,
    ) -> dict[str, Any] | None:
        text = (evidence or "").strip()
        if not self.enabled or not text:
            return None

        questions = {
            "event_type": {
                "type": "choice",
                "instructions": "Which defensive investigation event family best matches this evidence?",
                "criteria": {
                    "authentication": "Authentication, login, account or credential event",
                    "network": "Network traffic, connection, DNS, firewall or routing event",
                    "endpoint": "Host, process, file, persistence or endpoint behavior",
                    "malware_indicator": "Malware, malicious file, IOC or suspicious executable evidence",
                    "phishing_social": "Phishing, social engineering, malicious message or impersonation",
                    "data_access": "Unexpected data access, exfiltration indicator or sensitive-data event",
                    "configuration_change": "System, network, access-control or application configuration change",
                    "osint": "Open-source intelligence observation requiring correlation",
                    "other": "Another investigation event",
                },
            },
            "severity": {
                "type": "score",
                "instructions": "How urgently should an authorized investigator review this evidence?",
                "criteria": ["informational", "low", "medium", "high"],
            },
            "suspicious": {
                "type": "noul",
                "instructions": "Does the supplied evidence appear suspicious enough to merit investigation?",
            },
            "needs_network_review": {
                "type": "noul",
                "instructions": "Should network evidence be correlated as part of the investigation?",
            },
            "needs_endpoint_review": {
                "type": "noul",
                "instructions": "Should endpoint or host evidence be correlated as part of the investigation?",
            },
            "human_escalation": {
                "type": "noul",
                "instructions": "Should a qualified human investigator review this before any containment or remediation action?",
            },
        }

        payload = {
            "state": {
                "evidence": text[:12000],
                "source": source,
                "case_id": case_id,
                "policy": {
                    "advisory_only": True,
                    "deterministic_ioc_and_forensic_rules_remain_authoritative": True,
                    "no_scanning_exploitation_containment_or_file_action": True,
                    "human_authorization_required_for_remediation": True,
                },
            },
            "questions": questions,
        }
        headers = {"content-type": "application/json", "accept": "application/json"}
        if self.api_key:
            headers["authorization"] = "Bearer " + self.api_key

        started = time.perf_counter()
        try:
            body = self._request_fn(
                self.base_url + "/v1/systemone",
                json.dumps(payload).encode("utf-8"),
                headers,
                self.timeout_seconds,
            )
            answers = body.get("answers")
            if not isinstance(answers, dict):
                raise ValueError("System-One response has no answers object")
            return {
                "provider": "laya",
                "mode": self.mode,
                "advisory_only": True,
                "answers": answers,
                "routing": body.get("routing") if isinstance(body.get("routing"), dict) else None,
                "usage": body.get("usage") if isinstance(body.get("usage"), dict) else None,
                "latency_ms": int((time.perf_counter() - started) * 1000),
            }
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            socket.timeout,
            TimeoutError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ):
            return None


def format_decision(decision: dict[str, Any] | None) -> str:
    if decision is None:
        return "System-One is disabled or unavailable; deterministic Horus investigation remains unchanged."
    return json.dumps(decision, indent=2, sort_keys=True)
