from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    campaigns_using_s0096 = mitre_attack_data.get_campaigns_using_software_with_id('tool--7fcbc4e8-1989-441f-9ac5-e7b6ff5806f1')
    print(f"Campaigns using S0096 ({len(campaigns_using_s0096)}):")
    for c in campaigns_using_s0096:
        campaign = c['object']
        print(f"* {campaign.name} ({mitre_attack_data.get_attack_id(campaign.id)})")


if __name__ == "__main__":
    main()
