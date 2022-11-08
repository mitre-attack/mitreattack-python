from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all campaigns related to software
    campaigns_using_software = mitre_attack_data.get_campaigns_using_software()
    print(f"Campaigns using software ({len(campaigns_using_software.keys())} software):")
    for id, campaigns in campaigns_using_software.items():
        print(f"* {id} - used by {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")

    # get campaigns related to S0096
    campaigns_using_s0096 = campaigns_using_software['tool--7fcbc4e8-1989-441f-9ac5-e7b6ff5806f1']
    print(f"\nCampaigns using S0096 ({len(campaigns_using_s0096)}):")
    for c in campaigns_using_s0096:
        campaign = c['object']
        print(f"* {campaign.name} ({mitre_attack_data.get_attack_id(campaign.id)})")


if __name__ == "__main__":
    main()
