import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    # get all campaigns related to techniques
    campaigns_using_techniques = mitre_attack_data.get_all_campaigns_using_all_techniques()

    print(f"Campaigns using techniques ({len(campaigns_using_techniques.keys())} techniques):")
    for id, campaigns in campaigns_using_techniques.items():
        print(f"* {id} - used by {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")


if __name__ == "__main__":
    main()
