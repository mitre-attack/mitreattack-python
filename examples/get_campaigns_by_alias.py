from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    campaigns = mitre_attack_data.get_campaigns_by_alias("Frankenstein")

    for campaign in campaigns:
        print(f"{campaign.name} ({mitre_attack_data.get_attack_id(campaign.id)})")


if __name__ == "__main__":
    main()
