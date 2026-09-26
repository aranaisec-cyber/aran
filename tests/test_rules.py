from pathlib import Path

from mcp_shield.rules import (
    DEFAULT_INPUT_SIGNATURES,
    DEFAULT_OUTPUT_SIGNATURES,
    INPUT_KEY,
    OUTPUT_KEY,
    load_rules,
    load_rules_detailed,
)


def test_load_rules_reads_valid_yaml(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "input_gate_signatures:\n"
        "  - \"ignore previous instructions\"\n"
        "output_gate_signatures:\n"
        "  - \"rm\\\\s+-[rfRF]+\"\n",
        encoding="utf-8",
    )

    input_sigs, output_sigs = load_rules(rules_file)

    assert input_sigs == ["ignore previous instructions"]
    assert output_sigs == [r"rm\s+-[rfRF]+"]


def test_load_rules_missing_file_returns_defaults(tmp_path: Path):
    missing = tmp_path / "does-not-exist.yaml"

    input_sigs, output_sigs = load_rules(missing)

    assert input_sigs == list(DEFAULT_INPUT_SIGNATURES)
    assert output_sigs == list(DEFAULT_OUTPUT_SIGNATURES)


def test_load_rules_malformed_yaml_returns_defaults(tmp_path: Path):
    rules_file = tmp_path / "broken.yaml"
    rules_file.write_text("input_gate_signatures: [unterminated", encoding="utf-8")

    input_sigs, output_sigs = load_rules(rules_file)

    assert input_sigs == list(DEFAULT_INPUT_SIGNATURES)
    assert output_sigs == list(DEFAULT_OUTPUT_SIGNATURES)


def test_load_rules_empty_file_returns_defaults(tmp_path: Path):
    rules_file = tmp_path / "empty.yaml"
    rules_file.write_text("", encoding="utf-8")

    input_sigs, output_sigs = load_rules(rules_file)

    assert input_sigs == list(DEFAULT_INPUT_SIGNATURES)
    assert output_sigs == list(DEFAULT_OUTPUT_SIGNATURES)


def test_load_rules_non_mapping_yaml_scalar_returns_defaults(tmp_path: Path):
    rules_file = tmp_path / "scalar.yaml"
    rules_file.write_text("just a plain scalar string, not a mapping", encoding="utf-8")

    input_sigs, output_sigs = load_rules(rules_file)

    assert input_sigs == list(DEFAULT_INPUT_SIGNATURES)
    assert output_sigs == list(DEFAULT_OUTPUT_SIGNATURES)


def test_load_rules_non_mapping_yaml_list_returns_defaults(tmp_path: Path):
    rules_file = tmp_path / "list.yaml"
    rules_file.write_text("- a\n- b\n", encoding="utf-8")

    input_sigs, output_sigs = load_rules(rules_file)

    assert input_sigs == list(DEFAULT_INPUT_SIGNATURES)
    assert output_sigs == list(DEFAULT_OUTPUT_SIGNATURES)


# --- I7: malformed (but validly-parsed) signature values --------------------

def test_load_rules_string_instead_of_list_falls_back_not_split_per_character(tmp_path: Path):
    rules_file = tmp_path / "string.yaml"
    rules_file.write_text(
        "input_gate_signatures: \"ignore previous instructions\"\n"
        "output_gate_signatures:\n  - \"rm\\\\s+-rf\"\n",
        encoding="utf-8",
    )

    result = load_rules_detailed(rules_file)

    # A bare string used to become one signature per character, which then
    # matched virtually every message - a false-positive DoS.
    assert result.input_signatures == list(DEFAULT_INPUT_SIGNATURES)
    assert "e" not in result.input_signatures
    assert result.output_signatures == [r"rm\s+-rf"]
    assert INPUT_KEY in result.fallback_reasons
    assert OUTPUT_KEY not in result.fallback_reasons


def test_load_rules_non_string_element_falls_back(tmp_path: Path):
    rules_file = tmp_path / "numeric.yaml"
    rules_file.write_text(
        "input_gate_signatures:\n  - ignore previous instructions\n"
        "output_gate_signatures:\n  - 123\n  - \"rm\\\\s+-rf\"\n",
        encoding="utf-8",
    )

    result = load_rules_detailed(rules_file)

    assert result.input_signatures == ["ignore previous instructions"]
    assert result.output_signatures == list(DEFAULT_OUTPUT_SIGNATURES)
    assert all(isinstance(sig, str) for sig in result.output_signatures)
    assert OUTPUT_KEY in result.fallback_reasons


def test_load_rules_mapping_value_falls_back(tmp_path: Path):
    rules_file = tmp_path / "mapping.yaml"
    rules_file.write_text("input_gate_signatures:\n  a: b\n", encoding="utf-8")

    result = load_rules_detailed(rules_file)

    assert result.input_signatures == list(DEFAULT_INPUT_SIGNATURES)
    assert result.used_fallback


# --- I4: the caller has to be able to tell a fallback happened --------------

def test_load_rules_detailed_reports_no_fallback_for_a_healthy_file(tmp_path: Path):
    rules_file = tmp_path / "ok.yaml"
    rules_file.write_text(
        "input_gate_signatures:\n  - one\noutput_gate_signatures:\n  - two\n",
        encoding="utf-8",
    )

    result = load_rules_detailed(rules_file)

    assert not result.used_fallback
    assert result.fallback_reasons == {}


def test_load_rules_detailed_reports_missing_file(tmp_path: Path):
    result = load_rules_detailed(tmp_path / "nope.yaml")

    assert result.used_fallback
    assert "not found" in result.fallback_reasons[INPUT_KEY]
    assert "not found" in result.fallback_reasons[OUTPUT_KEY]


def test_load_rules_detailed_reports_unparseable_file(tmp_path: Path):
    rules_file = tmp_path / "broken.yaml"
    rules_file.write_text("input_gate_signatures: [unterminated", encoding="utf-8")

    result = load_rules_detailed(rules_file)

    assert "YAML" in result.fallback_reasons[INPUT_KEY]
