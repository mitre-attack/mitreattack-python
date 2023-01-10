from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    matrices = mitre_attack_data.get_matrices(remove_revoked_deprecated=True)

    print(f"Retrieved {len(matrices)} ATT&CK matrices: { ', '.join([m.name for m in matrices]) }")


if __name__ == "__main__":
    main()
