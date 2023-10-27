from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("ics-attack.json")

    assets = mitre_attack_data.get_assets(remove_revoked_deprecated=True)

    print(f"Retrieved {len(assets)} ICS assets.")


if __name__ == "__main__":
    main()
