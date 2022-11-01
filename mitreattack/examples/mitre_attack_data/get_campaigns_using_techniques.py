from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get all campaigns related to techniques
    campaigns_using_techniques = mitre_attack_data.get_campaigns_using_techniques()
    print(f"Campaigns using techniques ({len(campaigns_using_techniques.keys())} techniques):")
    for id, campaigns in campaigns_using_techniques.items():
        print(f"* {id} - used by {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")

    # get campaigns related to T1049
    campaigns_using_t1049 = campaigns_using_techniques['attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475']
    print(f"\nCampaigns using T1049 ({len(campaigns_using_t1049)}):")
    for c in campaigns_using_t1049:
        campaign = c['object']
        print(f"* {campaign.name} ({mitre_attack_data.get_attack_id(campaign.id)})")


if __name__ == "__main__":
    main()
