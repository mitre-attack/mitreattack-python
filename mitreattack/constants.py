"""Constants used throughout the mitreattack library."""

# The ATT&CK ID entry always has a source_name with a value from:
# ['mitre-attack', 'mitre-mobile-attack', 'mobile-attack', 'mitre-ics-attack']
MITRE_ATTACK_ID_SOURCE_NAMES = ["mitre-attack", "mobile-attack", "mitre-mobile-attack", "mitre-ics-attack"]
MITRE_ATTACK_DOMAIN_STRINGS = ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]

# Lookup module for Platforms - each matrix has a list of possible platforms, and each platform with multiple
#   subplatforms has a corresponding entry. This allows for a pseudo-recursive lookup of subplatforms, as the presence
#   of a platform at the top level of this lookup indicates the existence of subplatforms.
PLATFORMS_LOOKUP = {
    "enterprise-attack": [
        "PRE",
        "Windows",
        "macOS",
        "Linux",
        "Cloud",
        "Office Suite",
        "Identity Provider",
        "SaaS",
        "IaaS",
        "Network Devices",
        "Containers",
        "ESXi",
    ],
    "mobile-attack": ["Android", "iOS"],
    "Cloud": ["Office Suite", "Identity Provider", "SaaS", "IaaS"],
    "ics-attack": [
        "Field Controller/RTU/PLC/IED",
        "Safety Instrumented System/Protection Relay",
        "Control Server",
        "Input/Output Server",
        "Windows",
        "Human-Machine Interface",
        "Engineering Workstation",
        "Data Historian",
    ],
}
