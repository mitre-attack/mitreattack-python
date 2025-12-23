import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all campaigns related to groups
    campaigns_attributed = mitre_attack_data.get_all_campaigns_attributed_to_all_groups()

    print(f"Campaigns attributed to groups ({len(campaigns_attributed.keys())} groups):")
    for id, campaigns in campaigns_attributed.items():
        print(f"* {id} - attributing to {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")


if __name__ == "__main__":
    main()
