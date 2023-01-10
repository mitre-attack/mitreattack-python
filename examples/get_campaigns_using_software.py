from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get campaigns related to S0096
    software_stix_id = "tool--7fcbc4e8-1989-441f-9ac5-e7b6ff5806f1"
    campaigns_using_s0096 = mitre_attack_data.get_campaigns_using_software(software_stix_id)

    print(f"Campaigns using S0096 ({len(campaigns_using_s0096)}):")
    for c in campaigns_using_s0096:
        campaign = c["object"]
        print(f"* {campaign.name} ({mitre_attack_data.get_attack_id(campaign.id)})")


if __name__ == "__main__":
    main()
