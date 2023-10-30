"""Constants used throughout the mitreattack library."""

# The ATT&CK ID entry always has a source_name with a value from:
# ['mitre-attack', 'mitre-mobile-attack', 'mobile-attack', 'mitre-ics-attack']
MITRE_ATTACK_ID_SOURCE_NAMES = ["mitre-attack", "mobile-attack", "mitre-mobile-attack", "mitre-ics-attack"]
MITRE_ATTACK_DOMAIN_STRINGS = ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]

PLATFORMS_LOOKUP = {
    "enterprise-attack": [
        "PRE",
        "Windows",
        "macOS",
        "Linux",
        "Cloud",
        "Office 365",
        "Azure AD",
        "Google Workspace",
        "SaaS",
        "IaaS",
        "Network",
        "Containers",
    ],
    "mobile-attack": ["Android", "iOS"],
    "Cloud": ["Office 365", "Azure AD", "Google Workspace", "SaaS", "IaaS"],
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
