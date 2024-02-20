from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # retrieve techniques by the content of their description
    techniques = mitre_attack_data.get_objects_by_content("LSASS", "attack-pattern", remove_revoked_deprecated=True)
    print(f"There are {len(techniques)} techniques where 'LSASS' appears in the description.")
    
	# retrieve all objects by the content of their description
    objects = mitre_attack_data.get_objects_by_content("LSASS", None, remove_revoked_deprecated=True)
    print(f"There are a total of {len(objects)} objects where 'LSASS' appears in the description.")


if __name__ == "__main__":
    main()
