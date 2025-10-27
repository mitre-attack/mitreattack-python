import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get groups related to C0011
    campaign_stix_id = "campaign--b4e5a4a9-f3be-4631-ba8f-da6ebb067fac"
    groups_attributing_to_c0011 = mitre_attack_data.get_groups_attributing_to_campaign(campaign_stix_id)

    print(f"Groups attributing to C0011 ({len(groups_attributing_to_c0011)}):")
    for g in groups_attributing_to_c0011:
        group = g["object"]
        print(f"* {group.name} ({mitre_attack_data.get_attack_id(group.id)})")


if __name__ == "__main__":
    main()
