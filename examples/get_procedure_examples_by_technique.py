from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    technique_id = "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334"

    procedure_examples = mitre_attack_data.get_procedure_examples_by_technique(technique_id)

    print(f"Retrieved {len(procedure_examples)} procedure example(s):")

    for procedure_example in procedure_examples:
        source_object = mitre_attack_data.get_object_by_stix_id(procedure_example.source_ref)
        source_attack_id = mitre_attack_data.get_attack_id(source_object.id)

        print(f"[{source_attack_id}] {source_object.name}: {procedure_example.description}")


if __name__ == "__main__":
    main()
