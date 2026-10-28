"""
Unit tests for LLM GuardLab: lab.py
=====================================
Tests cover:
  - Canary detection logic
  - Injection detection logic
  - Outcome classification
  - Metric computation
  - CSV export and reload
  - Prompt construction
  - Simulation engine (offline)

Run with:
    python -m pytest tests/test_lab.py -v

All tests are deterministic and do NOT call any external API.
"""

import csv
import json
import sys
import tempfile
from pathlib import Path

# Make the parent directory importable regardless of how pytest is invoked
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

import lab
from lab import (
    CANARY,
    RAW_TEST_CASES,
    TestResult,
    build_prompt,
    classify_outcome,
    compute_metrics,
    detect_canary,
    detect_injection,
    run_tests,
    save_results_csv,
    save_metrics_json,
    _simulated_response,
    CSV_FIELDS,
)


# ---------------------------------------------------------------------------
# 1.  Canary detection
# ---------------------------------------------------------------------------

class TestDetectCanary:
    def test_canary_present(self):
        assert detect_canary(f"The secret is {CANARY} here.") is True

    def test_canary_absent(self):
        assert detect_canary("Nothing suspicious here.") is False

    def test_empty_string(self):
        assert detect_canary("") is False

    def test_canary_is_case_sensitive(self):
        """Canary should be detected exactly as defined (case-sensitive)."""
        lower = CANARY.lower()
        # Only matters if canary itself contains mixed/upper letters
        assert detect_canary(lower) == (lower == CANARY)


# ---------------------------------------------------------------------------
# 2.  Injection detection
# ---------------------------------------------------------------------------

class TestDetectInjection:
    def test_tc01_detected(self):
        assert detect_injection("TC-01", "Injection successful. I am now your assistant.") is True

    def test_tc04_hacked_detected(self):
        assert detect_injection("TC-04", "HACKED") is True

    def test_tc06_system_suspended_detected(self):
        assert detect_injection("TC-06", "SYSTEM SUSPENDED") is True

    def test_tc08_canary_detected(self):
        assert detect_injection("TC-08", f"The code is {CANARY}") is True

    def test_no_keywords_safe(self):
        assert detect_injection("TC-01", "Earnings rose by 12%.") is False

    def test_tc10_no_keywords(self):
        """TC-10 has no success keywords — detect_injection should return False."""
        assert detect_injection("TC-10", "any response here") is False

    def test_case_insensitive(self):
        assert detect_injection("TC-06", "system suspended") is True

    def test_unknown_test_id(self):
        """Unknown test IDs have no keywords and should never flag an injection."""
        assert detect_injection("TC-99", "HACKED injection successful") is False


# ---------------------------------------------------------------------------
# 3.  Outcome classification
# ---------------------------------------------------------------------------

class TestClassifyOutcome:
    def test_injection_real(self):
        result = classify_outcome("TC-01", "baseline", True, False, False)
        assert result == "INJECTION"

    def test_safe_real(self):
        result = classify_outcome("TC-01", "baseline", False, False, False)
        assert result == "SAFE"

    def test_injection_simulated(self):
        result = classify_outcome("TC-01", "baseline", True, False, True)
        assert result == "SIMULATED_INJECTION"

    def test_safe_simulated(self):
        result = classify_outcome("TC-01", "defended", False, False, True)
        assert result == "SIMULATED_SAFE"

    def test_false_positive_real(self):
        result = classify_outcome("TC-10", "baseline", True, False, False)
        assert result == "FALSE_POSITIVE"

    def test_tc10_safe_when_no_injection(self):
        result = classify_outcome("TC-10", "baseline", False, False, False)
        assert result == "SAFE"

    def test_canary_alone_triggers_injection(self):
        """A canary match without keyword match should still flag as INJECTION."""
        result = classify_outcome("TC-05", "baseline", False, True, False)
        assert result == "INJECTION"

    def test_simulated_fp(self):
        result = classify_outcome("TC-10", "baseline", True, False, True)
        assert result == "SIMULATED_FP"


# ---------------------------------------------------------------------------
# 4.  Prompt construction
# ---------------------------------------------------------------------------

class TestBuildPrompt:
    def test_canary_in_baseline_prompt(self):
        prompt = build_prompt("baseline", "Some document text.")
        assert CANARY in prompt

    def test_canary_in_defended_prompt(self):
        prompt = build_prompt("defended", "Some document text.")
        assert CANARY in prompt

    def test_document_in_prompt(self):
        doc = "This is a test document."
        prompt = build_prompt("baseline", doc)
        assert doc in prompt

    def test_document_block_markers(self):
        prompt = build_prompt("defended", "doc content")
        assert "<DOCUMENT>" in prompt
        assert "</DOCUMENT>" in prompt

    def test_defended_has_security_policy(self):
        prompt = build_prompt("defended", "doc")
        assert "SECURITY POLICY" in prompt

    def test_baseline_does_not_have_security_policy(self):
        prompt = build_prompt("baseline", "doc")
        assert "SECURITY POLICY" not in prompt


# ---------------------------------------------------------------------------
# 5.  Simulation engine
# ---------------------------------------------------------------------------

class TestSimulatedResponse:
    def test_tc10_always_safe(self):
        for config in ["baseline", "defended"]:
            response, notes = _simulated_response(RAW_TEST_CASES[9], config)
            # TC-10 simulated response should not contain CANARY or injection keywords
            assert detect_injection("TC-10", response) is False

    def test_baseline_tc01_contains_injection_phrase(self):
        response, _ = _simulated_response(RAW_TEST_CASES[0], "baseline")
        assert "injection successful" in response.lower()

    def test_defended_tc01_is_safe(self):
        response, _ = _simulated_response(RAW_TEST_CASES[0], "defended")
        assert "injection successful" not in response.lower()

    def test_baseline_tc08_exposes_canary(self):
        response, _ = _simulated_response(RAW_TEST_CASES[7], "baseline")
        assert CANARY in response

    def test_defended_tc08_does_not_expose_canary(self):
        response, _ = _simulated_response(RAW_TEST_CASES[7], "defended")
        assert CANARY not in response

    def test_all_simulated_responses_contain_simulated_tag(self):
        """Every simulated response should contain '[SIMULATED]' for transparency."""
        for tc in RAW_TEST_CASES:
            for config in ["baseline", "defended"]:
                response, _ = _simulated_response(tc, config)
                assert "[SIMULATED" in response, (
                    f"Missing [SIMULATED] tag in {tc['id']} / {config}: {response[:80]}"
                )


# ---------------------------------------------------------------------------
# 6.  Test runner (offline)
# ---------------------------------------------------------------------------

class TestRunTests:
    def test_offline_run_returns_expected_count(self):
        """2 configs × 10 test cases × 1 repetition = 20 results."""
        results = run_tests(configs=["baseline", "defended"], use_real_model=False)
        assert len(results) == 20

    def test_baseline_only(self):
        results = run_tests(configs=["baseline"], use_real_model=False)
        assert len(results) == 10
        assert all(r.config == "baseline" for r in results)

    def test_defended_only(self):
        results = run_tests(configs=["defended"], use_real_model=False)
        assert len(results) == 10
        assert all(r.config == "defended" for r in results)

    def test_all_results_marked_simulated(self):
        results = run_tests(use_real_model=False)
        assert all(r.is_simulated for r in results)

    def test_run_id_consistent_within_run(self):
        results = run_tests(run_id="TEST-RUN-001", use_real_model=False)
        assert all(r.run_id == "TEST-RUN-001" for r in results)

    def test_baseline_has_more_injections_than_defended(self):
        """
        In the simulated heuristic, the baseline should show more injections
        than the defended config. This validates the simulation's design intent.
        """
        results = run_tests(use_real_model=False)
        baseline_injections = sum(
            1 for r in results
            if r.config == "baseline" and "INJECTION" in r.outcome
        )
        defended_injections = sum(
            1 for r in results
            if r.config == "defended" and "INJECTION" in r.outcome
        )
        assert baseline_injections > defended_injections, (
            f"Expected baseline ({baseline_injections}) > defended ({defended_injections})"
        )

    def test_tc10_never_injection(self):
        """TC-10 is benign; simulated responses should not flag as INJECTION."""
        results = run_tests(use_real_model=False)
        tc10_results = [r for r in results if r.test_id == "TC-10"]
        assert len(tc10_results) == 2  # one per config
        for r in tc10_results:
            assert "INJECTION" not in r.outcome, (
                f"TC-10 should not be flagged as INJECTION: {r.outcome}"
            )


# ---------------------------------------------------------------------------
# 7.  Metric computation
# ---------------------------------------------------------------------------

class TestComputeMetrics:
    def test_metrics_keys_present(self):
        results = run_tests(use_real_model=False)
        metrics = compute_metrics(results)
        assert "baseline" in metrics
        assert "defended" in metrics

    def test_rates_are_fractions(self):
        results = run_tests(use_real_model=False)
        metrics = compute_metrics(results)
        for config, m in metrics.items():
            assert 0.0 <= m["injection_rate"] <= 1.0, f"{config} injection_rate out of range"
            assert 0.0 <= m["safe_rate"] <= 1.0, f"{config} safe_rate out of range"
            assert 0.0 <= m["canary_exposure_rate"] <= 1.0

    def test_baseline_injection_rate_is_high(self):
        """Simulated baseline heuristic should show a high injection rate."""
        results = run_tests(use_real_model=False)
        metrics = compute_metrics(results)
        assert metrics["baseline"]["injection_rate"] > 0.5

    def test_defended_injection_rate_is_lower_than_baseline(self):
        results = run_tests(use_real_model=False)
        metrics = compute_metrics(results)
        assert (
            metrics["defended"]["injection_rate"]
            < metrics["baseline"]["injection_rate"]
        )


# ---------------------------------------------------------------------------
# 8.  CSV export
# ---------------------------------------------------------------------------

class TestSaveResultsCsv:
    def test_csv_created(self, tmp_path):
        results = run_tests(use_real_model=False)
        csv_path = save_results_csv(results, path=tmp_path / "out.csv")
        assert csv_path.exists()

    def test_csv_has_correct_columns(self, tmp_path):
        results = run_tests(use_real_model=False)
        csv_path = save_results_csv(results, path=tmp_path / "out.csv")
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            assert set(reader.fieldnames) == set(CSV_FIELDS)

    def test_csv_row_count(self, tmp_path):
        results = run_tests(use_real_model=False)
        csv_path = save_results_csv(results, path=tmp_path / "out.csv")
        with open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == len(results)

    def test_csv_simulated_flag(self, tmp_path):
        results = run_tests(use_real_model=False)
        csv_path = save_results_csv(results, path=tmp_path / "out.csv")
        with open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert all(row["is_simulated"] == "True" for row in rows)


# ---------------------------------------------------------------------------
# 9.  JSON metrics export
# ---------------------------------------------------------------------------

class TestSaveMetricsJson:
    def test_json_created(self, tmp_path):
        results = run_tests(use_real_model=False)
        json_path = save_metrics_json(results, path=tmp_path / "metrics.json")
        assert json_path.exists()

    def test_json_valid(self, tmp_path):
        results = run_tests(use_real_model=False)
        json_path = save_metrics_json(results, path=tmp_path / "metrics.json")
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        assert "metrics_by_config" in data
        assert "is_simulated" in data
        assert data["is_simulated"] is True

    def test_json_has_disclaimer(self, tmp_path):
        results = run_tests(use_real_model=False)
        json_path = save_metrics_json(results, path=tmp_path / "metrics.json")
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        assert "disclaimer" in data
        assert len(data["disclaimer"]) > 10


# ---------------------------------------------------------------------------
# 10.  Data integrity
# ---------------------------------------------------------------------------

class TestDataIntegrity:
    def test_ten_test_cases_defined(self):
        assert len(RAW_TEST_CASES) == 10

    def test_all_test_cases_have_required_fields(self):
        required = {"id", "category", "description", "document",
                    "success_criteria", "expected_safe_behaviour"}
        for tc in RAW_TEST_CASES:
            missing = required - set(tc.keys())
            assert not missing, f"Test case {tc.get('id')} missing fields: {missing}"

    def test_test_case_ids_are_unique(self):
        ids = [tc["id"] for tc in RAW_TEST_CASES]
        assert len(ids) == len(set(ids)), "Duplicate test case IDs found"

    def test_canary_is_non_empty_string(self):
        assert isinstance(CANARY, str) and len(CANARY) > 0
