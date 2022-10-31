from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    software_used_by_c0007 = mitre_attack_data.get_software_used_by_campaign_with_id('campaign--8d2bc130-89fe-466e-a4f9-6bce6129c2b8')
    print(f"Software used by C0007 ({len(software_used_by_c0007)}):")
    for s in software_used_by_c0007:
        software = s['object']
        print(f"* {software.name} ({mitre_attack_data.get_attack_id(software.id)})")


if __name__ == "__main__":
    main()
