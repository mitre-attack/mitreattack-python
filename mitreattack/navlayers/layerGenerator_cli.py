"""Entrypoint for the layer generator cli."""

import argparse
import os

from mitreattack.navlayers.generators.overview_generator import OverviewLayerGenerator
from mitreattack.navlayers.generators.usage_generator import UsageLayerGenerator
from mitreattack.navlayers.generators.sum_generator import BatchGenerator


def main(argv=None):
    """Entrypoint for layerGenerator_cli."""
    parser = argparse.ArgumentParser(description="Generate an ATT&CK Navigator layer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--overview-type",
        choices=["group", "software", "mitigation", "datasource", "campaign", "asset"],
        help="Output a layer file where the target type is summarized across the entire dataset.",
    )
    group.add_argument(
        "--mapped-to",
        help="Output layer file with techniques mapped to the given group, software, "
        "mitigation, data component, campaign, or asset. Argument can be name, associated "
        "group/software, or ATT&CK ID.",
    )
    group.add_argument(
        "--batch-type",
        choices=["group", "software", "mitigation", "datasource", "campaign", "asset"],
        help="Output a collection of layer files to the specified folder, each one representing a "
        "different instance of the target type.",
    )
    parser.add_argument("-o", "--output", help="Path to the output layer file/directory", default="generated_layer")
    parser.add_argument(
        "--domain", help="Which domain to build off of", choices=["enterprise", "mobile", "ics"], default="enterprise"
    )
    parser.add_argument(
        "--source",
        choices=["local", "remote"],
        default="local",
        help="What source to utilize when building the layer files",
    )
    parser.add_argument(
        "--resource",
        help="Path to the local resource if --source=local, or url of an ATT&CK Workbench"
        " instance if --source=remote",
        default=None,
    )
    args = parser.parse_args(args=argv)

    if args.overview_type:
        og = OverviewLayerGenerator(source=args.source, domain=args.domain, resource=args.resource)
        generated = og.generate_layer(obj_type=args.overview_type)
        print("Generating Layer File")
        out_path = args.output
        if out_path == "generated_layer":
            out_path += ".json"
        generated.to_file(out_path)
        print(f"Layer file generated as {out_path}.")
    elif args.mapped_to:
        ug = UsageLayerGenerator(source=args.source, domain=args.domain, resource=args.resource)
        generated = ug.generate_layer(match=args.mapped_to)
        print("Generating Layer File")
        out_path = args.output
        if out_path == "generated_layer":
            out_path += ".json"
        generated.to_file(out_path)
        print(f"Layer file generated as {out_path}.")
    elif args.batch_type:
        bg = BatchGenerator(source=args.source, domain=args.domain, resource=args.resource)
        generated = bg.generate_layers(layers_type=args.batch_type)
        out_path = args.output
        if out_path == "generated_layer":
            out_path += "s"
        if not os.path.exists(out_path):
            os.makedirs(out_path)
        for sid in generated:
            generated[sid].to_file(f"{out_path}/{sid}.json")
        print(f"Files saved to {out_path}/")


if __name__ == "__main__":
    main()
