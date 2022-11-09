from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get parent technique of T1195.002
    subtechnique_stix_id = 'attack-pattern--bd369cd9-abb8-41ce-b5bb-fff23ee86c00'
    parent_of_t1195_002 = mitre_attack_data.get_parent_technique_of_subtechnique(subtechnique_stix_id)
    p = parent_of_t1195_002[0]['object']

    print(f"Parent technique of T1195.002: {p.name} ({mitre_attack_data.get_attack_id(p.id)})")


if __name__ == "__main__":
    main()
