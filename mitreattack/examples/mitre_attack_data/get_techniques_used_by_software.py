from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    # get all techniques related to software
    techniques_used_by_software = mitre_attack_data.get_techniques_used_by_software()
    print(f"Techniques used by software ({len(techniques_used_by_software.keys())} software):")
    for id, techniques_used in techniques_used_by_software.items():
        print(f"* {id} - {len(techniques_used)} {'technique' if len(techniques_used) == 1 else 'techniques'} used")

    # get techniques used by S0349
    techniques_used_by_s0349 = techniques_used_by_software['tool--b76b2d94-60e4-4107-a903-4a3a7622fb3b']
    print(f"\nTechniques used by S0349 ({len(techniques_used_by_s0349)}):")
    for t in techniques_used_by_s0349:
        technique = t['object']
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")


if __name__ == "__main__":
    main()
