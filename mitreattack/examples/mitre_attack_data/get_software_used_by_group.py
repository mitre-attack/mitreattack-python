from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get software used by G0019
    group_stix_id = 'intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050'
    software_used_by_g0019 = mitre_attack_data.get_software_used_by_group(group_stix_id)
    
    print(f"Software used by G0019 ({len(software_used_by_g0019)}):")
    for s in software_used_by_g0019:
        software = s['object']
        print(f"* {software.name} ({mitre_attack_data.get_attack_id(software.id)})")


if __name__ == "__main__":
    main()
