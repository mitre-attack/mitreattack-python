from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    campaigns_using_software = mitre_attack_data.get_campaigns_using_software()
    print(f"Campaigns using software ({len(campaigns_using_software.keys())}):")
    for id, campaigns in campaigns_using_software.items():
        print(f"* {id} - used by {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")


if __name__ == "__main__":
    main()
