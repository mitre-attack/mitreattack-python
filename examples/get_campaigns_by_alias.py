import os

from mitreattack.stix20 import MitreAttackData


def main():
    stix_filepath = os.environ.get("STIX_BUNDLE", "enterprise-attack.json")
    mitre_attack_data = MitreAttackData(stix_filepath=stix_filepath)

    campaigns = mitre_attack_data.get_campaigns_by_alias("Frankenstein")

    for campaign in campaigns:
        print(f"{campaign.name} ({mitre_attack_data.get_attack_id(campaign.id)})")


if __name__ == "__main__":
    main()
