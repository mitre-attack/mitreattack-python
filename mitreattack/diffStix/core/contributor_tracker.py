"""Contributor tracking for ATT&CK changelog generation."""

from typing import Dict, Optional


class ContributorTracker:
    """Track new contributors across ATT&CK releases."""

    def __init__(self):
        """Initialize the contributor tracker."""
        self.release_contributors: Dict[str, int] = {}

    def update_contributors(self, old_object: Optional[dict], new_object: dict):
        """Update release contributors with any new contributors.

        Parameters
        ----------
        old_object : Optional[dict]
            Old version of an ATT&CK STIX Domain Object (SDO). Can be None for new additions.
        new_object : dict
            New version of an ATT&CK STIX Domain Object (SDO).
        """
        if new_object.get("x_mitre_contributors"):
            new_object_contributors = set(new_object["x_mitre_contributors"])

            # Check if old objects had contributors
            if old_object is None or not old_object.get("x_mitre_contributors"):
                old_object_contributors = set()
            else:
                old_object_contributors = set(old_object["x_mitre_contributors"])

            # Remove old contributors from showing up
            # if contributors are the same the result will be empty
            new_contributors = new_object_contributors - old_object_contributors

            # Update counter of contributor to track contributions
            for new_contributor in new_contributors:
                if self.release_contributors.get(new_contributor):
                    self.release_contributors[new_contributor] += 1
                else:
                    self.release_contributors[new_contributor] = 1

    def get_contributor_section(self) -> str:
        """Generate a markdown section listing new contributors.

        Returns
        -------
        str
            Markdown formatted string of new contributors and their contribution counts.
        """
        contribSection = "## Contributors to this release\n\n"
        sorted_contributors = sorted(self.release_contributors, key=lambda v: v.lower())

        for contributor in sorted_contributors:
            # do not include ATT&CK as contributor
            if contributor == "ATT&CK":
                continue
            contribSection += f"* {contributor}\n"

        return contribSection

    def get_contributors_list(self) -> list:
        """Get list of new contributors sorted alphabetically.

        Returns
        -------
        list
            Sorted list of contributor names.
        """
        return sorted(self.release_contributors.keys())

    def get_contributor_count(self, contributor: str) -> int:
        """Get the number of contributions for a specific contributor.

        Parameters
        ----------
        contributor : str
            Name of the contributor.

        Returns
        -------
        int
            Number of contributions, or 0 if contributor not found.
        """
        return self.release_contributors.get(contributor, 0)
