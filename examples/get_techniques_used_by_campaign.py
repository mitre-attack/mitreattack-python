import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get techniques used by C0011
    campaign_stix_id = "campaign--b4e5a4a9-f3be-4631-ba8f-da6ebb067fac"
    techniques_used_by_c0011 = mitre_attack_data.get_techniques_used_by_campaign(campaign_stix_id)

    print(f"Techniques used by C0011 ({len(techniques_used_by_c0011)}):")
    for t in techniques_used_by_c0011:
        technique = t["object"]
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
