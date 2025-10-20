"""Print comprehensive ATT&CK statistics across all domains."""

import os
from dataclasses import dataclass

from mitreattack.stix20 import MitreAttackData

# Get STIX base directory from environment or use default
STIX_BASE_DIR = os.environ.get("STIX_BASE_DIR", "attack-releases/stix-2.0/v17.1")


@dataclass
class DomainStatistics:
    """Statistics for a single ATT&CK domain."""

    name: str
    tactics: int
    techniques: int
    subtechniques: int
    groups: int
    software: int
    campaigns: int
    mitigations: int
    datasources: int
    assets: int = 0

    def format_output(self) -> str:
        """
        Format domain statistics as a string.

        Returns
        -------
        str
            Formatted statistics string for display.
        """
        # Define all possible statistics with their labels
        stats = [
            (self.tactics, "Tactics"),
            (self.techniques, "Techniques"),
            (self.subtechniques, "Sub-Techniques"),
            (self.groups, "Groups"),
            (self.software, "Pieces of Software"),
            (self.campaigns, "Campaigns"),
            (self.mitigations, "Mitigations"),
            (self.assets, "Assets"),
            (self.datasources, "Data Sources"),
        ]

        # Build parts list, only including items with count > 0
        parts = [f"{count} {label}" for count, label in stats if count > 0]

        # Join all parts with proper formatting
        return f"- {self.name}: {', '.join(parts[:-1])}, and {parts[-1]}"


def load_domain_data() -> dict[str, MitreAttackData]:
    """
    Load STIX data for all ATT&CK domains.

    Returns
    -------
    dict of str to MitreAttackData
        Mapping of domain names to loaded MitreAttackData objects.
    """
    domains = {
        "enterprise": "enterprise-attack.json",
        "mobile": "mobile-attack.json",
        "ics": "ics-attack.json",
    }

    return {
        domain: MitreAttackData(stix_filepath=os.path.join(STIX_BASE_DIR, filename))
        for domain, filename in domains.items()
    }


def collect_domain_statistics(data: MitreAttackData, domain_name: str) -> DomainStatistics:
    """
    Collect statistics for a single domain.

    Parameters
    ----------
    data : MitreAttackData
        The MitreAttackData object for the domain.
    domain_name : str
        Display name of the domain.

    Returns
    -------
    DomainStatistics
        Statistics for the domain.
    """
    # Get all object types, removing revoked and deprecated
    tactics = data.get_tactics(remove_revoked_deprecated=True)
    techniques = data.get_techniques(include_subtechniques=False, remove_revoked_deprecated=True)
    subtechniques = data.get_subtechniques(remove_revoked_deprecated=True)
    groups = data.get_groups(remove_revoked_deprecated=True)
    software = data.get_software(remove_revoked_deprecated=True)
    campaigns = data.get_campaigns(remove_revoked_deprecated=True)
    mitigations = data.get_mitigations(remove_revoked_deprecated=True)
    datasources = data.get_datasources(remove_revoked_deprecated=True)

    # ICS domain has assets
    assets = 0
    if domain_name == "ICS":
        assets = len(data.get_assets(remove_revoked_deprecated=True))

    return DomainStatistics(
        name=domain_name,
        tactics=len(tactics),
        techniques=len(techniques),
        subtechniques=len(subtechniques),
        groups=len(groups),
        software=len(software),
        campaigns=len(campaigns),
        mitigations=len(mitigations),
        datasources=len(datasources),
        assets=assets,
    )


def collect_unique_object_counts(domain_data: dict[str, MitreAttackData]) -> dict[str, int]:
    """
    Collect counts of unique objects across all domains.

    Some objects (Software, Groups, Campaigns) may appear in multiple domains.
    This function counts unique objects to avoid double-counting.

    Parameters
    ----------
    domain_data : dict of str to MitreAttackData
        Mapping of domain names to MitreAttackData objects.

    Returns
    -------
    dict of str to int
        Counts of unique software, groups, and campaigns.
    """
    all_software_ids = set()
    all_groups_ids = set()
    all_campaigns_ids = set()

    for data in domain_data.values():
        software = data.get_software(remove_revoked_deprecated=True)
        groups = data.get_groups(remove_revoked_deprecated=True)
        campaigns = data.get_campaigns(remove_revoked_deprecated=True)

        all_software_ids.update(obj["id"] for obj in software)
        all_groups_ids.update(obj["id"] for obj in groups)
        all_campaigns_ids.update(obj["id"] for obj in campaigns)

    return {
        "software": len(all_software_ids),
        "groups": len(all_groups_ids),
        "campaigns": len(all_campaigns_ids),
    }


def main():
    """Print ATT&CK statistics for all domains."""
    # Load data for all domains
    domain_data = load_domain_data()

    # Collect unique object counts across all domains
    unique_counts = collect_unique_object_counts(domain_data)

    # Collect statistics for each domain
    enterprise_stats = collect_domain_statistics(domain_data["enterprise"], "Enterprise")
    mobile_stats = collect_domain_statistics(domain_data["mobile"], "Mobile")
    ics_stats = collect_domain_statistics(domain_data["ics"], "ICS")

    # Print summary output
    print(
        f"This version of ATT&CK contains {unique_counts['software']} Pieces of Software, "
        f"{unique_counts['groups']} Groups, and {unique_counts['campaigns']} Campaigns"
    )
    print("Broken out by domain:\n")

    # Print domain statistics
    print(enterprise_stats.format_output())
    print(mobile_stats.format_output())
    print(ics_stats.format_output())


if __name__ == "__main__":
    main()
