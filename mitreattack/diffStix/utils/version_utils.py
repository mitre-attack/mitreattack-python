"""Version comparison and validation utilities for ATT&CK objects."""

from dataclasses import dataclass
from typing import Optional

from dateutil import parser as dateparser
from loguru import logger


@dataclass
class AttackObjectVersion:
    """An ATT&CK object version."""

    major: int
    minor: int

    def __repr__(self):
        """Return a string representation of the ATT&CK object version."""
        return f"{self.major}.{self.minor}"


def get_attack_object_version(stix_obj: dict) -> AttackObjectVersion:
    """Get the object's ATT&CK version.

    Parameters
    ----------
    stix_obj : dict
        An ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    AttackObjectVersion
        The object version of the ATT&CK object.
    """
    # ICS objects didn't have x_mitre_version until v11.0, so pretend they were version 0.0
    version = stix_obj.get("x_mitre_version", "0.0")
    major, minor = version.split(".")
    major = int(major)
    minor = int(minor)
    object_version = AttackObjectVersion(major=major, minor=minor)
    return object_version


def is_major_version_change(old_version: AttackObjectVersion, new_version: AttackObjectVersion) -> bool:
    """Determine if the new version is a major change."""
    if old_version is None or new_version is None:
        return False
    # Check if inputs are the correct type
    if not isinstance(old_version, AttackObjectVersion) or not isinstance(new_version, AttackObjectVersion):
        return False
    next_major_num = old_version.major + 1
    next_major_version = AttackObjectVersion(major=next_major_num, minor=0)
    if new_version == next_major_version:
        return True
    return False


def is_minor_version_change(old_version: AttackObjectVersion, new_version: AttackObjectVersion) -> bool:
    """Determine if the new version is a minor change."""
    if old_version is None or new_version is None:
        return False
    # Check if inputs are the correct type
    if not isinstance(old_version, AttackObjectVersion) or not isinstance(new_version, AttackObjectVersion):
        return False
    next_minor_num = old_version.minor + 1
    next_minor_version = AttackObjectVersion(major=old_version.major, minor=next_minor_num)
    if new_version == next_minor_version:
        return True
    return False


def is_other_version_change(old_version: AttackObjectVersion, new_version: AttackObjectVersion) -> bool:
    """Determine if the new version is an unexpected change."""
    if old_version is None or new_version is None:
        return False
    # Check if inputs are the correct type
    if not isinstance(old_version, AttackObjectVersion) or not isinstance(new_version, AttackObjectVersion):
        return False
    # either stayed the same or was a normal version change
    if is_major_version_change(old_version=old_version, new_version=new_version):
        return False
    elif is_minor_version_change(old_version=old_version, new_version=new_version):
        return False
    elif (old_version.major == new_version.major) and (old_version.minor == new_version.minor):
        return False

    # Possible scenarios
    # * went up by more than 0.1, but not next major version
    # * version number went down
    return True


def version_increment_is_valid(
    old_version: AttackObjectVersion | None, new_version: AttackObjectVersion | None, section: str
) -> bool:
    """Validate version increment between old and new STIX objects.

    Valid increments include the following:

        * Major version increases: e.g. 1.2 → 2.0
        * Minor version increases: e.g. 1.2 → 1.3
        * New version for new objects must be 1.0
        * Any value when section is "revocations" or "deprecations"

    Parameters
    ----------
    old_version : AttackObjectVersion | None
        Old version of an ATT&CK STIX Domain Object (SDO). Can be None for additions.
    new_version : AttackObjectVersion | None
        New version of an ATT&CK STIX Domain Object (SDO). Can be None for deletions.
    section : str
        Section change type, e.g major_version_change, revocations, etc.

    Returns
    -------
    bool
        Returns True when a valid version increment is found
    """
    if section in ["revocations", "deprecations"]:
        return True
    if section == "additions":
        if new_version != AttackObjectVersion(major=1, minor=0):
            return False
        return True
    if not (old_version and new_version):
        return False

    major_change = is_major_version_change(old_version=old_version, new_version=new_version)
    minor_change = is_minor_version_change(old_version=old_version, new_version=new_version)

    if major_change or minor_change:
        return True
    return False


def is_patch_change(old_stix_obj: dict, new_stix_obj: dict) -> bool:
    """Determine if ATT&CK Object changes are considered a patch change.

    Parameters
    ----------
    old_stix_obj : dict
        Old ATT&CK STIX Domain Object (SDO).
    new_stix_obj : dict
        New ATT&CK STIX Domain Object (SDO).

    Returns
    -------
    bool
        True if the object changed in such a way as to only be considered a patch change.
    """
    from .stix_utils import get_attack_id  # Import here to avoid circular dependency

    stix_id = new_stix_obj["id"]
    attack_id = get_attack_id(new_stix_obj)

    # Version stayed the same, but the modified date changed
    old_version = get_attack_object_version(old_stix_obj)
    new_version = get_attack_object_version(new_stix_obj)
    if new_version == old_version:
        old_date = dateparser.parse(old_stix_obj["modified"])
        new_date = dateparser.parse(new_stix_obj["modified"])
        if new_date != old_date:
            return True

    # description changed, even though modified date didn't
    if "description" in old_stix_obj and "description" in new_stix_obj:
        old_lines = old_stix_obj["description"].replace("\n", " ").splitlines()
        new_lines = new_stix_obj["description"].replace("\n", " ").splitlines()
        old_lines_unique = [line for line in old_lines if line not in new_lines]
        new_lines_unique = [line for line in new_lines if line not in old_lines]
        if old_lines_unique or new_lines_unique:
            logger.warning(
                f"{stix_id} - {attack_id} has a description change "
                "without the version being incremented or the last modified date changing"
            )
            return True

    # doesn't meet the definintion of a patch change
    return False
