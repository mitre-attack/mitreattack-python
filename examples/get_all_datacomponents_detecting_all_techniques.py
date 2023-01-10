from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    # get all data components related to techniques
    datacomponents_detecting = mitre_attack_data.get_all_datacomponents_detecting_all_techniques()

    print(f"Data components detecting techniques ({len(datacomponents_detecting.keys())} techniques):")
    for id, datacomponents in datacomponents_detecting.items():
        print(
            f"* {id} - detected by {len(datacomponents)} {'data component' if len(datacomponents) == 1 else 'data components'}"
        )


if __name__ == "__main__":
    main()
