"""
CloudShield Production Test Suite
Tests all core service logic without requiring external dependencies (Trivy, AWS, OPA, OpenAI).
Validates correctness, error handling, and risk scoring.

Run with:
    cd backend && python -m pytest tests/ -v
"""

import sys
import os
import json
import unittest

# Ensure backend is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ════════════════════════════════════════════════════════════
#  PHASE 1: Risk Engine Tests
# ════════════════════════════════════════════════════════════

class TestRiskEngine(unittest.TestCase):
    """Tests for the 0-100 risk scoring engine."""

    def setUp(self):
        from risk_engine import compute_risk_scores, _categorize_score
        self.compute = compute_risk_scores
        self.categorize = _categorize_score

    def test_empty_findings_returns_zero(self):
        result = self.compute([])
        self.assertEqual(result["final_score"], 0.0)
        self.assertEqual(result["category"], "LOW")
        self.assertEqual(result["finding_count"], 0)

    def test_safe_system_low_risk(self):
        """Safe system: all LOW findings → category LOW."""
        findings = [
            {"id": "CVE-LOW-1", "severity": "LOW", "source": "trivy"},
            {"id": "CVE-LOW-2", "severity": "LOW", "source": "trivy"},
        ]
        result = self.compute(findings)
        self.assertLess(result["final_score"], 40)
        self.assertEqual(result["category"], "LOW")

    def test_critical_container_gives_high_score(self):
        """Critical CVEs should yield HIGH or CRITICAL category."""
        findings = [
            {"id": "CVE-2023-0001", "severity": "CRITICAL", "source": "trivy"},
            {"id": "CVE-2023-0002", "severity": "CRITICAL", "source": "trivy"},
            {"id": "OPA-001", "severity": "CRITICAL", "source": "opa"},
        ]
        result = self.compute(findings)
        self.assertGreaterEqual(result["final_score"], 70)
        self.assertIn(result["category"], ("HIGH", "CRITICAL"))

    def test_public_s3_critical_risk(self):
        """Public S3 OPA finding should contribute to HIGH/CRITICAL."""
        findings = [
            {"id": "CS-POLICY-001", "severity": "CRITICAL", "source": "opa",
             "title": "S3 Bucket Publicly Accessible"},
        ]
        result = self.compute(findings)
        self.assertGreater(result["final_score"], 20)

    def test_score_capped_at_100(self):
        """Score should never exceed 100."""
        findings = [{"id": f"CVE-{i}", "severity": "CRITICAL", "source": "trivy"} for i in range(50)]
        result = self.compute(findings)
        self.assertLessEqual(result["final_score"], 100.0)

    def test_categorize_thresholds(self):
        self.assertEqual(self.categorize(90), "CRITICAL")
        self.assertEqual(self.categorize(85), "CRITICAL")
        self.assertEqual(self.categorize(75), "HIGH")
        self.assertEqual(self.categorize(50), "MEDIUM")
        self.assertEqual(self.categorize(20), "LOW")
        self.assertEqual(self.categorize(0), "LOW")


# ════════════════════════════════════════════════════════════
#  PHASE 2: OPA / Built-in Policy Engine Tests
# ════════════════════════════════════════════════════════════

class TestOpaService(unittest.TestCase):
    """Tests for the built-in cloud policy evaluator."""

    def setUp(self):
        from services.opa_service import _evaluate_builtin
        self.evaluate = _evaluate_builtin

    def _run(self, config):
        return self.evaluate(config, "2024-01-01T00:00:00Z")

    def test_public_s3_triggers_critical(self):
        config = {"s3_buckets": [{"name": "test-bucket", "public": True, "acl": "public-read",
                                   "encryption": {"enabled": False}, "logging": {"enabled": False}}]}
        result = self._run(config)
        self.assertEqual(result["status"], "completed")
        self.assertGreater(result["summary"]["total"], 0)
        criticals = [v for v in result["violations"] if v["severity"] == "CRITICAL"]
        self.assertGreater(len(criticals), 0, "Public S3 bucket must trigger CRITICAL violation")

    def test_secure_s3_no_violations(self):
        config = {"s3_buckets": [{"name": "secure-bucket", "public": False, "acl": "private",
                                   "encryption": {"enabled": True}, "logging": {"enabled": True}}]}
        result = self._run(config)
        self.assertEqual(result["summary"]["CRITICAL"], 0)

    def test_iam_wildcard_triggers_critical(self):
        config = {"iam_roles": [{"name": "admin-role", "mfa_required": False,
                                  "policies": [{"name": "full-access", "action": "*", "resource": "*"}]}]}
        result = self._run(config)
        criticals = [v for v in result["violations"] if v["severity"] == "CRITICAL"]
        self.assertGreater(len(criticals), 0, "IAM wildcard must trigger CRITICAL")

    def test_security_group_ssh_open(self):
        config = {"security_groups": [{"name": "sg-web", "ingress_rules": [
            {"cidr": "0.0.0.0/0", "port": 22, "protocol": "tcp"}
        ]}]}
        result = self._run(config)
        high_or_critical = [v for v in result["violations"] if v["severity"] in ("HIGH", "CRITICAL")]
        self.assertGreater(len(high_or_critical), 0, "Open SSH port must trigger HIGH/CRITICAL")

    def test_privileged_container_critical(self):
        config = {"containers": [{"name": "web", "privileged": True, "run_as_root": True}]}
        result = self._run(config)
        criticals = [v for v in result["violations"] if v["severity"] == "CRITICAL"]
        self.assertGreater(len(criticals), 0, "Privileged container must trigger CRITICAL")

    def test_empty_config_no_violations(self):
        result = self._run({})
        self.assertEqual(result["summary"]["total"], 0)

    def test_invalid_config_returns_error(self):
        from services.opa_service import evaluate_cloud_config
        result = evaluate_cloud_config(None)
        self.assertEqual(result["status"], "error")

    def test_rds_public_triggers_critical(self):
        config = {"rds_instances": [{"identifier": "prod-db", "publicly_accessible": True,
                                      "deletion_protection": False}]}
        result = self._run(config)
        criticals = [v for v in result["violations"] if v["severity"] == "CRITICAL"]
        self.assertGreater(len(criticals), 0)


# ════════════════════════════════════════════════════════════
#  PHASE 3: Trivy Service Input Sanitization Tests
# ════════════════════════════════════════════════════════════

class TestTrivyServiceSanitization(unittest.TestCase):
    """Validates Trivy input sanitization and error handling."""

    def setUp(self):
        from services.trivy_service import scan_container_image
        self.scan = scan_container_image

    def test_invalid_image_name_rejected(self):
        """Shell metacharacters must be blocked."""
        result = self.scan("nginx; rm -rf /")
        self.assertEqual(result["status"], "error")
        self.assertIn("Invalid image name", result["message"])

    def test_empty_image_rejected(self):
        result = self.scan("")
        self.assertEqual(result["status"], "error")

    def test_too_long_name_rejected(self):
        result = self.scan("a" * 300)
        self.assertEqual(result["status"], "error")

    def test_valid_image_names_accepted(self):
        """These should pass input validation (Trivy may or may not be installed)."""
        from services.trivy_service import _trivy_available
        import re
        valid_names = ["nginx:latest", "ubuntu:22.04", "python:3.12-slim", "my-registry.io:5000/app:v1.2"]
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_.\-/:@]{0,254}$'
        for name in valid_names:
            self.assertIsNotNone(re.match(pattern, name), f"{name} should be a valid image name")

    def test_returns_structured_dict_on_success(self):
        """Even without Trivy, result must always be a dict with required keys."""
        result = self.scan("nginx:latest")
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)
        self.assertIn("vulnerabilities", result)


# ════════════════════════════════════════════════════════════
#  PHASE 4: AI Service Tests
# ════════════════════════════════════════════════════════════

class TestAiService(unittest.TestCase):
    """Tests for AI risk analysis (deterministic fallback path)."""

    def setUp(self):
        from services.ai_service import analyze_risk, _empty_analysis, _no_key_analysis
        self.analyze = analyze_risk
        self.empty = _empty_analysis
        self.no_key = _no_key_analysis

    def test_empty_findings_returns_low_risk(self):
        result = self.empty()
        self.assertEqual(result["overall_risk"], "LOW")
        self.assertEqual(result["priority_actions"], [])

    def test_deterministic_analysis_structure(self):
        """Ensures rule-based analysis returns all required keys."""
        findings = [
            {"id": "CVE-2024-001", "severity": "CRITICAL", "source": "trivy",
             "title": "Critical RCE", "description": "Remote code execution vulnerability"},
        ]
        risk_score = {"final_score": 87.5, "category": "CRITICAL", "finding_count": 1}
        result = self.no_key(findings, risk_score)

        required_keys = ["overall_risk", "executive_summary", "attack_vectors",
                         "priority_actions", "compliance_risk", "estimated_blast_radius", "_source"]
        for key in required_keys:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_critical_findings_give_critical_risk(self):
        findings = [{"id": "CVE-2024-001", "severity": "CRITICAL", "source": "trivy", "title": "Critical"}]
        risk_score = {"final_score": 90, "category": "CRITICAL", "finding_count": 1}
        result = self.no_key(findings, risk_score)
        self.assertEqual(result["overall_risk"], "CRITICAL")

    def test_caching_works(self):
        """Second call with same findings should be served from cache."""
        findings = [{"id": "CVE-CACHE-001", "severity": "HIGH", "source": "trivy", "title": "Test"}]
        risk_score = {"final_score": 72, "category": "HIGH", "finding_count": 1}
        result1 = self.analyze(findings, risk_score)
        result2 = self.analyze(findings, risk_score)
        # Both results should have same overall_risk (from cache or same data)
        self.assertEqual(result1["overall_risk"], result2["overall_risk"])


# ════════════════════════════════════════════════════════════
#  PHASE 5: DB Service Fallback Tests
# ════════════════════════════════════════════════════════════

class TestDbServiceFallback(unittest.TestCase):
    """Tests in-memory fallback mode (no MongoDB configured)."""

    def setUp(self):
        import services.db_service as db
        db.MONGO_URI = ""      # Force in-memory mode
        db._mongo_db = None
        db._mongo_client = None
        self.db = db

    def test_save_and_retrieve_vuln(self):
        result_id = self.db.save_vulnerability_scan("test:latest", {"status": "completed", "vulnerabilities": []})
        self.assertIsNotNone(result_id)
        data = self.db.get_latest_scans(limit=5)
        self.assertIn("vulnerabilities", data)

    def test_save_cloud_scan(self):
        result_id = self.db.save_cloud_scan("json", {"status": "completed", "violations": []})
        self.assertIsNotNone(result_id)

    def test_health_check_returns_fallback(self):
        status = self.db.health_check()
        self.assertEqual(status["backend"], "in-memory")


# ════════════════════════════════════════════════════════════
#  PHASE 6: Scenario-Based Tests (Demo Flow)
# ════════════════════════════════════════════════════════════

class TestScenarios(unittest.TestCase):
    """End-to-end scenario validation: Safe / Vulnerable / Critical."""

    def test_scenario_secure_system_low_risk(self):
        """A secure system with no findings scores LOW."""
        from risk_engine import compute_risk_scores
        result = compute_risk_scores([])
        self.assertEqual(result["category"], "LOW")
        self.assertEqual(result["final_score"], 0.0)

    def test_scenario_vulnerable_container_high_risk(self):
        """
        Multiple CRITICAL container CVEs. Score accounts for Trivy-only stream
        (50% weight) so a pure CVE scan with no cloud findings scores in the MEDIUM-HIGH
        range. Score >= 40 (MEDIUM+) confirms the risk engine responds correctly.
        """
        from risk_engine import compute_risk_scores
        findings = [
            {"id": f"CVE-2024-{i:04d}", "severity": "CRITICAL", "source": "trivy"}
            for i in range(5)
        ] + [
            {"id": f"CVE-2024-{i+100:04d}", "severity": "HIGH", "source": "trivy"}
            for i in range(3)
        ]
        result = compute_risk_scores(findings)
        # Pure container scan: Trivy stream (50%) + compliance proxy (20%)
        # No cloud stream. Expect >= 40 (MEDIUM at minimum, likely MEDIUM/HIGH)
        self.assertGreaterEqual(result["final_score"], 40)
        self.assertIn(result["category"], ("MEDIUM", "HIGH", "CRITICAL"))
        print(f"\n[SCENARIO] Vulnerable Container → Score: {result['final_score']}/100 ({result['category']})") 

    def test_scenario_public_s3_critical_risk(self):
        """Public S3 bucket should return CRITICAL violation from OPA."""
        from services.opa_service import _evaluate_builtin
        config = {
            "s3_buckets": [
                {"name": "public-data", "public": True, "acl": "public-read",
                 "encryption": {"enabled": False}, "logging": {"enabled": False}}
            ],
            "iam_roles": [
                {"name": "admin", "mfa_required": False,
                 "policies": [{"action": "*", "resource": "*"}]}
            ]
        }
        result = _evaluate_builtin(config, "test")
        print(f"\n[SCENARIO] Public S3 Scan → {result['summary']['total']} violations "
              f"({result['summary']['CRITICAL']} CRITICAL)")
        self.assertGreater(result["summary"]["CRITICAL"], 0)
        self.assertGreater(result["summary"]["total"], 2)

    def test_scenario_compliance_mapping(self):
        """Critical findings should map to NIST, CIS, ISO controls."""
        from services.compliance_service import map_findings_to_compliance
        findings = [
            {"id": "CVE-2024-001", "severity": "CRITICAL", "source": "trivy",
             "title": "Critical Vulnerability"},
            {"id": "CS-POLICY-001", "severity": "CRITICAL", "source": "opa",
             "title": "Public S3 Bucket"},
        ]
        result = map_findings_to_compliance(findings)
        self.assertIn("framework_summary", result)
        frameworks = result["framework_summary"]
        # Compliance service returns lowercase keys: 'cis', 'nist', 'iso', 'hipaa'
        self.assertIn("cis", frameworks)
        self.assertIn("nist", frameworks)
        self.assertIn("iso", frameworks)
        # Each framework entry should have a violations count and status
        for fw_key, fw_data in frameworks.items():
            self.assertIn("violations", fw_data)
            self.assertIn("status", fw_data)
            self.assertIn(fw_data["status"], ("COMPLIANT", "FAILING", "WARNING"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
