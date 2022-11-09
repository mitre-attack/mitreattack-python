from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all software related to campaigns
    software_used_by_campaigns = mitre_attack_data.get_all_software_used_by_all_campaigns()
    
    print(f"Software used by campaigns ({len(software_used_by_campaigns.keys())} campaigns):")
    for id, software_used in software_used_by_campaigns.items():
        print(f"* {id} - {len(software_used)} software used")


if __name__ == "__main__":
    main()
