import argparse
from exporters.to_svg import ToSvg, SVGConfig
from exporters.to_excel import ToExcel
from core import Layer

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export an ATT&CK Navigator layer as a svg image or excel file')
    parser.add_argument('-m', '--mode', choices=['svg', 'excel'], required=True, help='The form to export the layers in')
    parser.add_argument('input', nargs='+', help='Path(s) to the file to export')
    parser.add_argument('-s','--source', choices=['taxii', 'local'], default='taxii', help='What source to utilize when building the matrix')
    parser.add_argument('--local', help='Path to the local resource if --source=local', default=None)
    parser.add_argument('-o','--output', nargs='+', help='Path(s) to the exported svg/xlsx file', required=True)
    parser.add_argument('-l', '--load_settings', help='[SVG Only] Path to a SVG configuration json to use when '
                                                      'rendering', default=None)
    parser.add_argument('-d', '--size', nargs=2, help='[SVG Only] X and Y size values (in inches) for SVG export (use '
                                                      '-l for other settings)', default=[8.5, 11], metavar=("WIDTH",
                                                                                                            "HEIGHT"))
    args = parser.parse_args()
    if len(args.output) != len(args.input):
        print('Mismatched number of output file paths to input file paths. Exiting...')

    for i in range(0, len(args.input)):
        entry = args.input[i]
        print('{}/{} - Beginning processing {}'.format(i + 1, len(args.input), entry))
        lay = Layer()
        try:
            lay.from_file(entry)
        except:
            print('Unable to load {}. Skipping...'.format(entry))
            continue
        if args.mode=='excel':
            if not args.output[i].endswith('.xlsx'):
                print('[ERROR] Unable to export {} as type: excel to {}'.format(entry, args.output[i]))
                continue
            exy = ToExcel(domain=lay.layer.domain, source=args.source, local=args.local)
            exy.to_xlsx(lay, filepath=args.output[i])
        else:
            if not args.output[i].endswith('.svg'):
                print('[ERROR] Unable to export {} as type: svg to {}'.format(entry, args.output[i]))
                continue
            conf = SVGConfig()
            if args.load_settings:
                conf.load_from_file(args.load_settings)
            if len(args.size) == 2:
                conf.width = float(args.size[0])
                conf.height = float(args.size[1])
            svy = ToSvg(domain=lay.layer.domain, source=args.source, local=args.local, config=conf)
            svy.to_svg(lay, filepath=args.output[i])
        print('{}/{} - Finished exporting {} to {}'.format(i + 1, len(args.input), entry, args.output[i]))


else:
    print('This script is intended as a commandline wrapper for exporting scripts in the library. '
          'It will only work if run as the main script.')