from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get all campaigns related to groups
    campaigns_attributed = mitre_attack_data.get_campaigns_attributed_to_groups()
    print(f"Campaigns attributed to groups ({len(campaigns_attributed.keys())} groups):")
    for id, campaigns in campaigns_attributed.items():
        print(f"* {id} - attributing to {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")

    # get campaigns related to G0134
    campaigns_attributed_to_g0134 = campaigns_attributed['intrusion-set--e44e0985-bc65-4a8f-b578-211c858128e3']
    print(f"\nCampaigns attributed to G0134 ({len(campaigns_attributed_to_g0134)}):")
    for c in campaigns_attributed_to_g0134:
        campaign = c['object']
        print(f"* {campaign.name} ({mitre_attack_data.get_attack_id(campaign.id)})")


if __name__ == "__main__":
    main()
