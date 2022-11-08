from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all software related to campaigns
    software_used_by_campaigns = mitre_attack_data.get_software_used_by_campaigns()
    print(f"Software used by campaigns ({len(software_used_by_campaigns.keys())} campaigns):")
    for id, software_used in software_used_by_campaigns.items():
        print(f"* {id} - {len(software_used)} software used")

    # get software used by C0007
    software_used_by_c0007 = software_used_by_campaigns['campaign--8d2bc130-89fe-466e-a4f9-6bce6129c2b8']
    print(f"\nSoftware used by C0007 ({len(software_used_by_c0007)}):")
    for s in software_used_by_c0007:
        software = s['object']
        print(f"* {software.name} ({mitre_attack_data.get_attack_id(software.id)})")


if __name__ == "__main__":
    main()
