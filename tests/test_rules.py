from pathlib import Path

from aran.rules import (
    DEFAULT_INPUT_SIGNATURES,
    DEFAULT_OUTPUT_SIGNATURES,
    DEFAULT_SECRET_SIGNATURES,
    DEFAULT_SUPPLY_CHAIN_SIGNATURES,
    INPUT_KEY,
    OUTPUT_KEY,
    SECRET_KEY,
    SUPPLY_CHAIN_KEY,
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


# --- secret_signatures / supply_chain_signatures: optional, newer keys ------
# Added for the GitHub repo scan feature. A rules file written before these
# existed must keep loading cleanly (built-in defaults, no warning) - only a
# file that HAS one of these keys with a malformed value should warn.

def test_load_rules_detailed_reads_secret_and_supply_chain_signatures(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "input_gate_signatures:\n  - one\n"
        "output_gate_signatures:\n  - two\n"
        "secret_signatures:\n  - AKIA[0-9A-Z]{16}\n"
        "supply_chain_signatures:\n  - curl\\s+.*\\|\\s*bash\n",
        encoding="utf-8",
    )

    result = load_rules_detailed(rules_file)

    assert result.secret_signatures == ["AKIA[0-9A-Z]{16}"]
    assert result.supply_chain_signatures == [r"curl\s+.*\|\s*bash"]
    assert not result.used_fallback


def test_load_rules_detailed_an_old_file_missing_the_new_keys_is_not_a_fallback(tmp_path: Path):
    """A rules file with only the original two keys (every file that existed
    before this feature was added) must load exactly as it always did - no
    warning just because it predates secret_signatures/supply_chain_signatures."""
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "input_gate_signatures:\n  - one\noutput_gate_signatures:\n  - two\n",
        encoding="utf-8",
    )

    result = load_rules_detailed(rules_file)

    assert result.secret_signatures == list(DEFAULT_SECRET_SIGNATURES)
    assert result.supply_chain_signatures == list(DEFAULT_SUPPLY_CHAIN_SIGNATURES)
    assert not result.used_fallback
    assert SECRET_KEY not in result.fallback_reasons
    assert SUPPLY_CHAIN_KEY not in result.fallback_reasons


def test_load_rules_detailed_malformed_secret_signatures_falls_back_and_warns(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "input_gate_signatures:\n  - one\noutput_gate_signatures:\n  - two\n"
        "secret_signatures: \"not-a-list\"\n",
        encoding="utf-8",
    )

    result = load_rules_detailed(rules_file)

    assert result.secret_signatures == list(DEFAULT_SECRET_SIGNATURES)
    assert result.used_fallback
    assert SECRET_KEY in result.fallback_reasons


def test_load_rules_detailed_missing_file_falls_back_on_all_four_keys(tmp_path: Path):
    result = load_rules_detailed(tmp_path / "nope.yaml")

    assert result.secret_signatures == list(DEFAULT_SECRET_SIGNATURES)
    assert result.supply_chain_signatures == list(DEFAULT_SUPPLY_CHAIN_SIGNATURES)
    assert SECRET_KEY in result.fallback_reasons
    assert SUPPLY_CHAIN_KEY in result.fallback_reasons
