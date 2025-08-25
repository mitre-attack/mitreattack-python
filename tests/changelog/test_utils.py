"""Shared test utilities for changelog tests.

This module contains common helper functions and assertion patterns used across
multiple changelog test files to reduce code duplication and improve maintainability.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

# ========================================
# Common Assertion Patterns
# ========================================


def assert_basic_markdown_structure(markdown_content: str) -> None:
    """Assert that markdown content has expected basic structure.

    Parameters
    ----------
    markdown_content : str
        The markdown content to validate

    Raises
    ------
    AssertionError
        If basic markdown structure is missing
    """
    assert isinstance(markdown_content, str), f"Expected string, got {type(markdown_content)}"
    assert len(markdown_content) > 0, "Markdown content should not be empty"
    assert "# " in markdown_content, "Markdown should contain headers"
    assert "Techniques" in markdown_content, "Markdown should contain Techniques section"


def assert_json_structure_valid(json_data: Dict[str, Any], expected_domains: List[str]) -> None:
    """Assert that JSON data has expected structure for changelog output.

    Parameters
    ----------
    json_data : dict
        The JSON data to validate
    expected_domains : list of str
        List of expected domain names

    Raises
    ------
    AssertionError
        If JSON structure is invalid
    """
    assert isinstance(json_data, dict), f"Expected dict, got {type(json_data)}"

    # Check that all expected domains are present
    for domain in expected_domains:
        assert domain in json_data, f"Missing domain '{domain}' in JSON data"

        # Check domain structure
        domain_data = json_data[domain]
        assert isinstance(domain_data, dict), f"Domain '{domain}' should be dict, got {type(domain_data)}"

        # Check that object types are present
        expected_types = [
            "techniques",
            "software",
            "groups",
            "campaigns",
            "assets",
            "mitigations",
            "datasources",
            "datacomponents",
            "detectionstrategies",
            "logsources",
            "analytics",
        ]
        for obj_type in expected_types:
            if obj_type in domain_data:  # Not all domains may have all types
                type_data = domain_data[obj_type]
                assert isinstance(type_data, dict), f"{domain}.{obj_type} should be dict"

                # Check change categories
                expected_categories = [
                    "additions",
                    "major_version_changes",
                    "minor_version_changes",
                    "other_version_changes",
                    "patches",
                    "revocations",
                    "deprecations",
                    "deletions",
                ]
                for category in expected_categories:
                    if category in type_data:  # Not all categories may be present
                        assert isinstance(type_data[category], list), f"{domain}.{obj_type}.{category} should be list"


def assert_layer_structure_valid(layer_data: Dict[str, Any], expected_domain: str) -> None:
    """Assert that layer data has expected ATT&CK Navigator structure.

    Parameters
    ----------
    layer_data : dict
        The layer data to validate
    expected_domain : str
        Expected domain name for this layer

    Raises
    ------
    AssertionError
        If layer structure is invalid
    """
    assert isinstance(layer_data, dict), f"Expected dict, got {type(layer_data)}"

    # Check required fields
    required_fields = {
        "name": str,
        "description": str,
        "domain": str,
        "versions": dict,
        "techniques": list,
        "sorting": int,
        "hideDisabled": bool,
        "legendItems": list,
        "showTacticRowBackground": bool,
        "tacticRowBackground": str,
        "selectTechniquesAcrossTactics": bool,
    }

    for field, expected_type in required_fields.items():
        assert field in layer_data, f"Missing required field '{field}' in layer"
        assert isinstance(layer_data[field], expected_type), (
            f"Field '{field}' should be {expected_type.__name__}, got {type(layer_data[field])}"
        )

    # Check versions structure
    versions = layer_data["versions"]
    version_fields = ["layer", "navigator", "attack"]
    for field in version_fields:
        assert field in versions, f"Missing version field '{field}'"
        # attack version can be None in some cases
        if field == "attack":
            assert versions[field] is None or isinstance(versions[field], str), (
                f"Version field '{field}' should be string or None, got {type(versions[field])}"
            )
        else:
            assert isinstance(versions[field], str), f"Version field '{field}' should be string"

    # Check domain matches
    assert layer_data["domain"] == expected_domain, f"Expected domain '{expected_domain}', got '{layer_data['domain']}'"


def assert_diffstix_data_structure_valid(diffstix_instance) -> None:
    """Assert that a DiffStix instance has valid data structure.

    Parameters
    ----------
    diffstix_instance
        DiffStix instance to validate

    Raises
    ------
    AssertionError
        If DiffStix data structure is invalid
    """
    # Check that data attribute exists and has expected structure
    assert hasattr(diffstix_instance, "data"), "DiffStix should have 'data' attribute"
    data = diffstix_instance.data
    assert isinstance(data, dict), "DiffStix.data should be dict"

    # Check for old/new/changes keys
    required_keys = ["old", "new", "changes"]
    for key in required_keys:
        assert key in data, f"Missing key '{key}' in DiffStix.data"
        assert isinstance(data[key], dict), f"DiffStix.data['{key}'] should be dict"

    # Check that domains are present in old and new
    assert hasattr(diffstix_instance, "domains"), "DiffStix should have 'domains' attribute"
    for domain in diffstix_instance.domains:
        assert domain in data["old"], f"Missing domain '{domain}' in old data"
        assert domain in data["new"], f"Missing domain '{domain}' in new data"


# ========================================
# File Creation and Validation Utilities
# ========================================


def create_test_files_and_validate(
    file_paths: Dict[str, Union[str, Path]], validation_funcs: Dict[str, callable]
) -> None:
    """Create test files and validate their contents.

    Parameters
    ----------
    file_paths : dict
        Mapping of file type to file path
    validation_funcs : dict
        Mapping of file type to validation function

    Raises
    ------
    AssertionError
        If file creation or validation fails
    """
    for file_type, file_path in file_paths.items():
        path_obj = Path(file_path)
        assert path_obj.exists(), f"{file_type} file should exist at {file_path}"

        if file_type in validation_funcs:
            validation_funcs[file_type](file_path)


def validate_markdown_file_content(file_path: Union[str, Path]) -> str:
    """Validate markdown file content and return it.

    Parameters
    ----------
    file_path : str or Path
        Path to the markdown file

    Returns
    -------
    str
        The markdown file content

    Raises
    ------
    AssertionError
        If file validation fails
    """
    path_obj = Path(file_path)
    assert path_obj.exists(), f"Markdown file should exist at {file_path}"

    content = path_obj.read_text()
    assert_basic_markdown_structure(content)
    return content


def validate_json_file_content(file_path: Union[str, Path], expected_domains: List[str]) -> Dict[str, Any]:
    """Validate JSON file content and return it.

    Parameters
    ----------
    file_path : str or Path
        Path to the JSON file
    expected_domains : list of str
        List of expected domains

    Returns
    -------
    dict
        The parsed JSON content

    Raises
    ------
    AssertionError
        If file validation fails
    """
    path_obj = Path(file_path)
    assert path_obj.exists(), f"JSON file should exist at {file_path}"

    with open(path_obj) as f:
        data = json.load(f)

    assert_json_structure_valid(data, expected_domains)
    return data


def validate_layer_file_content(file_path: Union[str, Path], expected_domain: str) -> Dict[str, Any]:
    """Validate layer file content and return it.

    Parameters
    ----------
    file_path : str or Path
        Path to the layer file
    expected_domain : str
        Expected domain name

    Returns
    -------
    dict
        The parsed layer content

    Raises
    ------
    AssertionError
        If file validation fails
    """
    path_obj = Path(file_path)
    assert path_obj.exists(), f"Layer file should exist at {file_path}"

    with open(path_obj) as f:
        data = json.load(f)

    assert_layer_structure_valid(data, expected_domain)
    return data


# ========================================
# Test Data Generation Helpers
# ========================================


def create_test_output_file_paths(tmp_path: Path, prefix: str = "test") -> Dict[str, str]:
    """Create standard test output file paths.

    Parameters
    ----------
    tmp_path : Path
        pytest tmp_path fixture
    prefix : str, optional
        Prefix for file names

    Returns
    -------
    dict
        Mapping of file type to file path string
    """
    return {
        "markdown": str(tmp_path / f"{prefix}.md"),
        "html": str(tmp_path / f"{prefix}.html"),
        "html_detailed": str(tmp_path / f"{prefix}_detailed.html"),
        "json": str(tmp_path / f"{prefix}.json"),
        "enterprise_layer": str(tmp_path / f"{prefix}_enterprise.json"),
        "mobile_layer": str(tmp_path / f"{prefix}_mobile.json"),
        "ics_layer": str(tmp_path / f"{prefix}_ics.json"),
    }


def create_layer_file_paths(tmp_path: Path, domains: List[str], prefix: str = "test") -> List[str]:
    """Create layer file paths for specified domains.

    Parameters
    ----------
    tmp_path : Path
        pytest tmp_path fixture
    domains : list of str
        List of domain names
    prefix : str, optional
        Prefix for file names

    Returns
    -------
    list of str
        List of layer file path strings
    """
    layer_files = []
    domain_mapping = {"enterprise-attack": "enterprise", "mobile-attack": "mobile", "ics-attack": "ics"}

    for domain in domains:
        domain_short = domain_mapping.get(domain, domain.replace("-attack", ""))
        layer_files.append(str(tmp_path / f"{prefix}_{domain_short}.json"))

    return layer_files


# ========================================
# Common Test Scenario Validators
# ========================================


def validate_comprehensive_output_generation(
    markdown_result: str, file_paths: Dict[str, str], expected_domains: List[str], layer_files: List[str] = None
) -> None:
    """Validate comprehensive output generation scenario.

    Parameters
    ----------
    markdown_result : str
        Returned markdown content
    file_paths : dict
        Mapping of file type to file path
    expected_domains : list of str
        List of expected domains
    layer_files : list of str, optional
        List of layer file paths to validate separately

    Raises
    ------
    AssertionError
        If validation fails
    """
    # Validate markdown return value
    assert_basic_markdown_structure(markdown_result)

    # Validate basic files were created and have correct structure
    basic_file_validation = {}
    if "markdown" in file_paths:
        basic_file_validation["markdown"] = lambda path: validate_markdown_file_content(path)
    if "json" in file_paths:
        basic_file_validation["json"] = lambda path: validate_json_file_content(path, expected_domains)

    # Only validate files that exist in file_paths
    files_to_validate = {k: v for k, v in file_paths.items() if k in basic_file_validation}
    if files_to_validate:
        create_test_files_and_validate(files_to_validate, basic_file_validation)

    # Validate layer files separately if provided
    if layer_files:
        for i, domain in enumerate(expected_domains):
            if i < len(layer_files):
                validate_layer_file_content(layer_files[i], domain)

    # Validate markdown file content matches return value
    if "markdown" in file_paths:
        file_content = Path(file_paths["markdown"]).read_text()
        assert file_content == markdown_result, "Markdown file content should match return value"


def validate_output_format_consistency(diffstix_instance, expected_domains: List[str]) -> None:
    """Validate that all output formats are consistent.

    Parameters
    ----------
    diffstix_instance
        DiffStix instance to test
    expected_domains : list of str
        List of expected domains

    Raises
    ------
    AssertionError
        If outputs are inconsistent
    """
    # Generate all outputs
    markdown = diffstix_instance.get_markdown_string()
    changes_dict = diffstix_instance.get_changes_dict()
    layers_dict = diffstix_instance.get_layers_dict()

    # Validate individual formats
    assert_basic_markdown_structure(markdown)
    assert_json_structure_valid(changes_dict, expected_domains)

    for domain in expected_domains:
        if domain in layers_dict:
            assert_layer_structure_valid(layers_dict[domain], domain)

    # Validate domain consistency across formats
    changes_domains = set(k for k in changes_dict.keys() if k != "new-contributors")
    layers_domains = set(layers_dict.keys())
    expected_domains_set = set(expected_domains)

    assert changes_domains == expected_domains_set, (
        f"Changes domains {changes_domains} don't match expected {expected_domains_set}"
    )
    assert layers_domains == expected_domains_set, (
        f"Layers domains {layers_domains} don't match expected {expected_domains_set}"
    )
