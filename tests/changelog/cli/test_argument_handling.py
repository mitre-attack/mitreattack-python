"""Tests for CLI argument parsing and validation."""

import sys

import pytest

from mitreattack.diffStix.changelog_helper import get_parsed_args


class TestArgumentHandling:
    """Comprehensive tests for CLI argument parsing and validation."""

    def _parse_args(self, argv_list, monkeypatch, setup_monkeypatch_args=None):
        """Parse arguments with monkeypatch setup."""
        if setup_monkeypatch_args:
            setup_monkeypatch_args(argv_list, monkeypatch)
        else:
            monkeypatch.setattr(sys, "argv", argv_list)
        return get_parsed_args()

    def _expect_system_exit(self, argv_list, monkeypatch, expected_code=None):
        """Test SystemExit scenarios."""
        monkeypatch.setattr(sys, "argv", argv_list)
        with pytest.raises(SystemExit) as exc_info:
            get_parsed_args()
        if expected_code is not None:
            assert exc_info.value.code == expected_code
        return exc_info

    def _assert_default_args(self, args):
        """Assert default argument values."""
        assert args.old == "old"
        assert args.new == "new"
        assert args.domains == ["enterprise-attack", "mobile-attack", "ics-attack"]
        assert args.unchanged is False
        assert args.show_key is False
        assert args.contributors is True
        assert args.verbose is False
        assert args.use_mitre_cti is False
        assert args.site_prefix == ""

    def test_get_parsed_args_default_values(self, monkeypatch):
        """Test default argument values."""
        args = self._parse_args(["script_name"], monkeypatch)
        self._assert_default_args(args)

    def test_get_parsed_args_all_options(self, monkeypatch):
        """Test parsing with all command-line options specified."""
        test_args = [
            "script_name",
            "--old",
            "old_data",
            "--new",
            "new_data",
            "--domains",
            "enterprise-attack",
            "--markdown-file",
            "test.md",
            "--html-file",
            "test.html",
            "--html-file-detailed",
            "detailed.html",
            "--json-file",
            "test.json",
            "--layers",
            "layer1.json",
            "layer2.json",
            "layer3.json",
            "--site_prefix",
            "https://example.com",
            "--unchanged",
            "--show-key",
            "--no-contributors",
            "--verbose",
        ]

        args = self._parse_args(test_args, monkeypatch)

        assert args.old == "old_data"
        assert args.new == "new_data"
        assert args.domains == ["enterprise-attack"]
        assert args.markdown_file == "test.md"
        assert args.html_file == "test.html"
        assert args.html_file_detailed == "detailed.html"
        assert args.json_file == "test.json"
        assert args.layers == ["layer1.json", "layer2.json", "layer3.json"]
        assert args.site_prefix == "https://example.com"
        assert args.unchanged is True
        assert args.show_key is True
        assert args.contributors is False
        assert args.verbose is True

    @pytest.mark.parametrize(
        "test_args,expected_exit_code,description",
        [
            (["script_name", "--old", "old_data", "--use-mitre-cti"], None, "mutually exclusive options"),
            (["script_name", "--help"], 0, "help option"),
            (["script_name", "--invalid-option"], None, "invalid option"),
            (["script_name", "--old"], None, "missing required value"),
        ],
    )
    def test_get_parsed_args_system_exit_scenarios(self, test_args, expected_exit_code, description, monkeypatch):
        """Test various scenarios that should cause SystemExit."""
        exc_info = self._expect_system_exit(test_args, monkeypatch, expected_exit_code)
        if expected_exit_code is not None:
            assert exc_info.value.code == expected_exit_code

    @pytest.mark.parametrize(
        "layers_input,expected_result,should_exit",
        [
            ([], [], False),  # Empty list is valid
            (
                ["enterprise.json", "mobile.json", "ics.json"],
                ["enterprise.json", "mobile.json", "ics.json"],
                False,
            ),  # Three files is valid
            (["layer1.json", "layer2.json"], None, True),  # Wrong count - need 0 or 3
        ],
    )
    def test_get_parsed_args_layer_validation(self, layers_input, expected_result, should_exit, monkeypatch):
        """Test layer argument validation scenarios."""
        test_args = ["script_name", "--layers"] + layers_input

        if should_exit:
            self._expect_system_exit(test_args, monkeypatch)
        else:
            args = self._parse_args(test_args, monkeypatch)
            assert args.layers == expected_result

    def test_get_parsed_args_logging_configuration_verbose(self, monkeypatch):
        """Test logging configuration in verbose mode."""
        args = self._parse_args(["script_name", "--verbose"], monkeypatch)
        assert args.verbose is True

    def test_get_parsed_args_logging_configuration_normal(self, monkeypatch):
        """Test logging configuration in normal mode."""
        args = self._parse_args(["script_name"], monkeypatch)
        assert args.verbose is False

    @pytest.mark.parametrize(
        "domains_input,expected_domains",
        [
            (["enterprise-attack"], ["enterprise-attack"]),
            (["enterprise-attack", "mobile-attack"], ["enterprise-attack", "mobile-attack"]),
            (
                ["enterprise-attack", "mobile-attack", "ics-attack"],
                ["enterprise-attack", "mobile-attack", "ics-attack"],
            ),
        ],
    )
    def test_get_parsed_args_domains(self, domains_input, expected_domains, monkeypatch):
        """Test parsing with various domain configurations."""
        test_args = ["script_name", "--domains"] + domains_input
        args = self._parse_args(test_args, monkeypatch)
        assert args.domains == expected_domains

    @pytest.mark.parametrize(
        "flag,expected_attr,expected_value",
        [
            ("--unchanged", "unchanged", True),
            ("--show-key", "show_key", True),
            ("--no-contributors", "contributors", False),
            ("--verbose", "verbose", True),
            ("--use-mitre-cti", "use_mitre_cti", True),
        ],
    )
    def test_get_parsed_args_boolean_flags(self, flag, expected_attr, expected_value, monkeypatch):
        """Test individual boolean flags."""
        test_args = ["script_name", flag]
        args = self._parse_args(test_args, monkeypatch)
        assert getattr(args, expected_attr) == expected_value

    @pytest.mark.parametrize(
        "option,value,expected_attr",
        [
            ("--old", "custom_old", "old"),
            ("--new", "custom_new", "new"),
            ("--markdown-file", "custom.md", "markdown_file"),
            ("--html-file", "custom.html", "html_file"),
            ("--html-file-detailed", "detailed.html", "html_file_detailed"),
            ("--json-file", "custom.json", "json_file"),
            ("--site_prefix", "https://custom.com", "site_prefix"),
            ("--site_prefix", "", "site_prefix"),  # Empty site prefix
            ("--site_prefix", "https://example.com/", "site_prefix"),  # With trailing slash
        ],
    )
    def test_get_parsed_args_string_options(self, option, value, expected_attr, monkeypatch):
        """Test individual string options."""
        test_args = ["script_name", option, value]
        args = self._parse_args(test_args, monkeypatch)
        assert getattr(args, expected_attr) == value
