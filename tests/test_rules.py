from pathlib import Path

from mcp_shield.rules import (
    DEFAULT_INPUT_SIGNATURES,
    DEFAULT_OUTPUT_SIGNATURES,
    load_rules,
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
