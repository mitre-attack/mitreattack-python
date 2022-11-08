from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get parent techniques of sub-techniques
    parent_techniques = mitre_attack_data.get_parent_techniques_of_subtechniques()
    print(f"Parent techniques of sub-techniques ({len(parent_techniques.keys())} sub-techniques):")
    for id, parent_technique in parent_techniques.items():
        parent = parent_technique[0]['object']
        print(f"* {parent.id} is the parent of {id}")

    # get parent technique of T1195.002
    parent_of_t1195_002 = parent_techniques['attack-pattern--bd369cd9-abb8-41ce-b5bb-fff23ee86c00']
    p = parent_of_t1195_002[0]['object']
    print(f"\nParent technique of T1195.002: {p.name} ({mitre_attack_data.get_attack_id(p.id)})")


if __name__ == "__main__":
    main()
