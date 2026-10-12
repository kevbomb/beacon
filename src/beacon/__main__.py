"""Launch either Beacon chat client: python -m beacon gui|cli."""

import argparse
import sys


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description="Beacon Wi-Fi chat: choose gui or cli")
    parser.add_argument("mode", choices=("gui", "cli"), nargs="?", default="gui")
    # Leave client flags (including --help) for the selected client's parser.
    if argv and argv[0] in ("gui", "cli"):
        mode = argv.pop(0)
    else:
        args, argv = parser.parse_known_args(argv)
        mode = args.mode
    if mode == "cli":
        from beacon.client.cli import main as launch
    else:
        from beacon.client.gui import main as launch
    return launch(argv)


if __name__ == "__main__":
    raise SystemExit(main())
