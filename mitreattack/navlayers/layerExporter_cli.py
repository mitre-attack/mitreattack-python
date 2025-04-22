"""Entrypoint for the layer exporter cli."""

import argparse

from mitreattack.navlayers.exporters.to_svg import ToSvg, SVGConfig
from mitreattack.navlayers.exporters.to_excel import ToExcel
from mitreattack.navlayers.core import Layer


def main(argv=None):
    """Entrypoint for layerExporter_cli."""
    parser = argparse.ArgumentParser(description="Export an ATT&CK Navigator layer as a svg image or excel file")
    parser.add_argument(
        "-m", "--mode", choices=["svg", "excel"], required=True, help="The form to export the layers in"
    )
    parser.add_argument("input", nargs="+", help="Path(s) to the file to export")
    parser.add_argument(
        "-s",
        "--source",
        choices=["local", "remote"],
        default="local",
        help="What source to utilize when building the matrix",
    )
    parser.add_argument(
        "--resource",
        help="Path to the local resource if --source=local, or url of an ATT&CK Workbench"
        " instance if --source=remote",
        default=None,
    )
    parser.add_argument("-o", "--output", nargs="+", help="Path(s) to the exported svg/xlsx file", required=True)
    parser.add_argument(
        "-l",
        "--load_settings",
        help="[SVG Only] Path to a SVG configuration json to use when " "rendering",
        default=None,
    )
    parser.add_argument(
        "-d",
        "--size",
        nargs=2,
        help="[SVG Only] X and Y size values (in inches) for SVG export (use " "-l for other settings)",
        default=[8.5, 11],
        metavar=("WIDTH", "HEIGHT"),
    )
    args = parser.parse_args(args=argv)

    if len(args.output) != len(args.input):
        print("Mismatched number of output file paths to input file paths. Exiting...")
        return

    for i in range(0, len(args.input)):
        entry = args.input[i]
        print(f"{i + 1}/{len(args.input)} - Beginning processing {entry}")
        lay = Layer()
        try:
            lay.from_file(entry)
        except Exception as e:
            print(f"Unable to load {entry} due to exception: {e}. Skipping...")
            continue
        if args.mode == "excel":
            if not args.output[i].endswith(".xlsx"):
                print(f"[ERROR] Unable to export {entry} as type: excel to {args.output[i]}")
                continue
            exy = ToExcel(domain=lay.layer.domain, source=args.source, resource=args.resource)
            exy.to_xlsx(lay, filepath=args.output[i])
        else:
            if not args.output[i].endswith(".svg"):
                print(f"[ERROR] Unable to export {entry} as type: svg to {args.output[i]}")
                continue
            conf = SVGConfig()
            if args.load_settings:
                conf.load_from_file(args.load_settings)
            if len(args.size) == 2:
                conf.width = float(args.size[0])
                conf.height = float(args.size[1])
            svy = ToSvg(domain=lay.layer.domain, source=args.source, resource=args.resource, config=conf)
            svy.to_svg(lay, filepath=args.output[i])
        print(f"{i + 1}/{len(args.input)} - Finished exporting {entry} to {args.output[i]}")


if __name__ == "__main__":
    main()
