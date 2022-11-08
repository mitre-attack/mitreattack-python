from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all software related to groups
    software_used_by_groups = mitre_attack_data.get_software_used_by_groups()
    print(f"Software used by groups ({len(software_used_by_groups.keys())} groups):")
    for id, software_used in software_used_by_groups.items():
        print(f"* {id} - {len(software_used)} software used")

    # get software used by G0019
    software_used_by_g0019 = software_used_by_groups['intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050']
    print(f"\nSoftware used by G0019 ({len(software_used_by_g0019)}):")
    for s in software_used_by_g0019:
        software = s['object']
        print(f"* {software.name} ({mitre_attack_data.get_attack_id(software.id)})")


if __name__ == "__main__":
    main()
