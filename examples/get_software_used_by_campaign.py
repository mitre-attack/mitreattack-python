import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get software used by C0007
    campaign_stix_id = "campaign--8d2bc130-89fe-466e-a4f9-6bce6129c2b8"
    software_used_by_c0007 = mitre_attack_data.get_software_used_by_campaign(campaign_stix_id)

    print(f"Software used by C0007 ({len(software_used_by_c0007)}):")
    for s in software_used_by_c0007:
        software = s["object"]
        print(f"* {software.name} ({mitre_attack_data.get_attack_id(software.id)})")


if __name__ == "__main__":
    main()
