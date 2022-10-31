from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("path/to/enterprise-attack.json")

    techniques = mitre_attack_data.get_techniques_used_by_group_software('intrusion-set--44e43fad-ffcb-4210-abcf-eaaed9735f80')
    print(f"There are {len(techniques)} techniques used by APT39's software.")


if __name__ == "__main__":
    main()
