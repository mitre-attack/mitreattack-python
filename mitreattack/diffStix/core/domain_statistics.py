"""Domain statistics dataclass for ATT&CK changelog generation."""

from dataclasses import dataclass


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
    assets: int
    datasources: int
    detectionstrategies: int
    analytics: int
    datacomponents: int

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
            (self.software, "Software"),
            (self.campaigns, "Campaigns"),
            (self.mitigations, "Mitigations"),
            (self.assets, "Assets"),
            (self.datasources, "Data Sources"),
            (self.detectionstrategies, "Detection Strategies"),
            (self.analytics, "Analytics"),
            (self.datacomponents, "Data Components"),
        ]

        # Build parts list, only including items with count > 0
        parts = [f"{count} {label}" for count, label in stats if count > 0]

        # Join all parts with proper formatting
        if len(parts) == 0:
            return f"* {self.name}: No objects"
        elif len(parts) == 1:
            return f"* {self.name}: {parts[0]}"
        else:
            return f"* {self.name}: {', '.join(parts[:-1])}, and {parts[-1]}"
