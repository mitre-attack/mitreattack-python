"""Pytest command-line options for mitreattack-python."""


def pytest_addoption(parser):
    """Register pytest options for selecting ATT&CK STIX test data."""
    parser.addoption(
        "--stix-enterprise",
        action="store",
        default=None,
        help="Path to an Enterprise ATT&CK STIX bundle to use in tests.",
    )
    parser.addoption(
        "--stix-mobile",
        action="store",
        default=None,
        help="Path to a Mobile ATT&CK STIX bundle to use in tests.",
    )
    parser.addoption(
        "--stix-ics",
        action="store",
        default=None,
        help="Path to an ICS ATT&CK STIX bundle to use in tests.",
    )
    parser.addoption(
        "--attack-version",
        action="store",
        default=None,
        help="ATT&CK release version to download and use for STIX-backed tests.",
    )
    parser.addoption(
        "--stix-version",
        action="store",
        choices=("2.0", "2.1"),
        default="2.0",
        help="STIX version to download when --attack-version is used. Defaults to 2.0.",
    )
