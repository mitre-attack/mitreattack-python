"""Statistics collector for ATT&CK version data."""

from stix2 import MemoryStore

from mitreattack.diffStix.core.domain_statistics import DomainStatistics
from mitreattack.stix20 import MitreAttackData


class StatisticsCollector:
    """Collects and formats statistics from ATT&CK STIX data."""

    def __init__(self, diff_stix_instance):
        """Initialize StatisticsCollector with a DiffStix instance.

        Parameters
        ----------
        diff_stix_instance : DiffStix
            The DiffStix instance containing data and helper methods
        """
        self.diff_stix = diff_stix_instance

    def collect_domain_statistics(self, datastore: MemoryStore, domain_name: str) -> DomainStatistics:
        """Collect statistics for a single domain from a STIX datastore.

        Parameters
        ----------
        datastore : MemoryStore
            The STIX MemoryStore containing the domain data.
        domain_name : str
            Display name of the domain (e.g., "Enterprise", "Mobile", "ICS").

        Returns
        -------
        DomainStatistics
            Statistics for the domain.
        """
        # Create MitreAttackData instance from the datastore
        data = MitreAttackData(src=datastore)

        # Get all object types, removing revoked and deprecated
        tactics = data.get_tactics(remove_revoked_deprecated=True)
        techniques = data.get_techniques(include_subtechniques=False, remove_revoked_deprecated=True)
        subtechniques = data.get_subtechniques(remove_revoked_deprecated=True)
        groups = data.get_groups(remove_revoked_deprecated=True)
        software = data.get_software(remove_revoked_deprecated=True)
        campaigns = data.get_campaigns(remove_revoked_deprecated=True)
        mitigations = data.get_mitigations(remove_revoked_deprecated=True)
        assets = data.get_assets(remove_revoked_deprecated=True)
        datasources = data.get_datasources(remove_revoked_deprecated=True)
        detectionstrategies = data.get_detectionstrategies(remove_revoked_deprecated=True)
        analytics = data.get_analytics(remove_revoked_deprecated=True)
        datacomponents = data.get_datacomponents(remove_revoked_deprecated=True)

        return DomainStatistics(
            name=domain_name,
            tactics=len(tactics),
            techniques=len(techniques),
            subtechniques=len(subtechniques),
            groups=len(groups),
            software=len(software),
            campaigns=len(campaigns),
            mitigations=len(mitigations),
            assets=len(assets),
            datasources=len(datasources),
            detectionstrategies=len(detectionstrategies),
            analytics=len(analytics),
            datacomponents=len(datacomponents),
        )

    def collect_unique_object_counts(self, datastore_version: str) -> dict[str, int]:
        """Collect counts of unique objects across all domains for a specific version.

        Some objects (Software, Groups, Campaigns) may appear in multiple domains.
        This function counts unique objects to avoid double-counting.

        Parameters
        ----------
        datastore_version : str
            Either "old" or "new" to specify which version's data to analyze.

        Returns
        -------
        dict of str to int
            Counts of unique software, groups, and campaigns.
        """
        all_software_ids = set()
        all_groups_ids = set()
        all_campaigns_ids = set()

        for domain in self.diff_stix.domains:
            datastore = self.diff_stix.data[datastore_version][domain]["stix_datastore"]
            data = MitreAttackData(src=datastore)

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

    def generate_statistics_section(self, datastore_version: str = "new") -> str:
        """Generate a markdown section with ATT&CK statistics for all domains.

        Parameters
        ----------
        datastore_version : str, optional
            Either "old" or "new" to specify which version's statistics to generate.
            Defaults to "new".

        Returns
        -------
        str
            Markdown-formatted statistics section.
        """
        # Collect unique object counts across all domains
        unique_counts = self.collect_unique_object_counts(datastore_version)

        # Collect statistics for each domain
        domain_stats = []
        for domain in self.diff_stix.domains:
            datastore = self.diff_stix.data[datastore_version][domain]["stix_datastore"]
            domain_label = self.diff_stix.domain_to_domain_label[domain]
            stats = self.collect_domain_statistics(datastore, domain_label)
            domain_stats.append(stats)

        # Build the statistics section
        output = "## Statistics\n\n"
        output += (
            f"This version of ATT&CK contains {unique_counts['software']} Software, "
            f"{unique_counts['groups']} Groups, and {unique_counts['campaigns']} Campaigns.\n\n"
        )
        output += "Broken out by domain:\n\n"

        for stats in domain_stats:
            output += stats.format_output() + "\n"

        output += "\n"
        return output
