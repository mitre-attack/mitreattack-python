from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all techniques related to software
    techniques_used_by_software = mitre_attack_data.get_all_techniques_used_by_all_software()
    
    print(f"Techniques used by software ({len(techniques_used_by_software.keys())} software):")
    for id, techniques_used in techniques_used_by_software.items():
        print(f"* {id} - {len(techniques_used)} {'technique' if len(techniques_used) == 1 else 'techniques'} used")


if __name__ == "__main__":
    main()
