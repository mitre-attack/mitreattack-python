from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    tactics_map = mitre_attack_data.get_tactics_by_technique()
    matrix_map = mitre_attack_data.get_tactics_by_matrix()
    
    print(f"Retrieved {len(tactics_map)} techniques.")


if __name__ == "__main__":
    main()
