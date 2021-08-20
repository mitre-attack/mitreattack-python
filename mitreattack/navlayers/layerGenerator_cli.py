import argparse
import os

from mitreattack.navlayers.generators.overview_generator import OverviewLayerGenerator
from mitreattack.navlayers.generators.usage_generator import UsageLayerGenerator
from mitreattack.navlayers.generators.sum_generator import SumGenerator


def main():
    parser = argparse.ArgumentParser(description='Generate an ATT&CK Navigator layer')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--overview-type', choices=['group', 'software', 'mitigation'],
                       help='Output a matrix where the target type is summarized across the entire dataset.')
    group.add_argument('--mapped-to', help='Output techniques mapped to the given group, software, or mitigation. '
                                           'Argument can be name, associated group/software, or ATT&CK ID.')
    group.add_argument('--mass-type', choices=['group', 'software', 'mitigation'],
                       help='Output a collection of matrices to the specified folder, each one representing a '
                            'different instance of the target type.')
    parser.add_argument('-p', '--path', help='Path to the output layer directory (mass-type)',
                        default='generated_layers')
    parser.add_argument('-o', '--output', help='Path to the output layer file (output)', default='generated_layer.json')
    parser.add_argument('--domain', help='Which domain to build off of', choices=['enterprise', 'mobile', 'ics'],
                        default='enterprise')
    parser.add_argument('--source', choices=['taxii', 'local'], default='taxii',
                        help='What source to utilize when building the matrix')
    parser.add_argument('--local', help='Path to the local resource if --source=local', default=None)
    args = parser.parse_args()

    if args.overview_type:
        og = OverviewLayerGenerator(source=args.source, domain=args.domain, local=args.local)
        generated = og.generate_layer(obj_type=args.overview_type)
        print('Generating Layer File')
        generated.to_file(args.output)
        print(f'Layer file generated as {args.output}.')
    elif args.mapped_to:
        ug = UsageLayerGenerator(source=args.source, domain=args.domain, local=args.local)
        generated = ug.generate_layer(match=args.mapped_to)
        print('Generating Layer File')
        generated.to_file(args.output)
        print(f'Layer file generated as {args.output}.')
    elif args.mass_type:
        sg = SumGenerator(source=args.source, domain=args.domain, local=args.local)
        generated = sg.generate_layers(layers_type=args.mass_type)
        if not os.path.exists(args.path):
            os.mkdir(args.path)
        for sid in generated:
            generated[sid].to_file(f"{args.path}/{sid}.json")
        print(f"Files saved to {args.path}/")


if __name__ == '__main__':
    main()
