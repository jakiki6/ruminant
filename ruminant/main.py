from . import modules
from .buf import Buf
import argparse
import sys
import json
import tempfile
import os
import re

sys.set_int_max_str_digits(0)
sys.setrecursionlimit(1000000)

has_tqdm = False
print_filenames = False


def walk_helper(path, filename_regex):
    for root, _, files in os.walk(path):
        for file in files:
            file = os.path.join(root, file)

            if filename_regex.match(file) is None:
                continue

            yield file


def process(file, walk):
    if not walk:
        return json.dumps(modules.chew(file), indent=2, ensure_ascii=False)
        return

    buf = Buf(file)
    unknown = 0

    data = []
    while buf.available():
        entry = None

        with buf:
            try:
                entry = modules.chew(file, True)
                assert entry["type"] != "unknown"
            except Exception:
                entry = None

        if entry is not None:
            if unknown > 0:
                data.append({
                    "type": "unknown",
                    "length": unknown,
                    "offset": buf.tell() - unknown,
                    "blob-id": modules.blob_id
                })
                modules.blob_id += 1
                unknown = 0

            data.append(entry)
            buf.skip(entry["length"])
        else:
            unknown += 1
            buf.skip(1)

    if unknown > 0:
        data.append({
            "type": "unknown",
            "length": unknown,
            "offset": buf.tell() - unknown,
            "blob-id": modules.blob_id
        })

    for entry in data:
        for k, v in modules.to_extract:
            if k == entry["blob-id"]:
                buf.seek(entry["offset"])
                with open(v, "wb") as file:
                    length = entry["length"]

                    while length:
                        blob = buf.read(min(1 << 24, length))
                        file.write(blob)
                        length -= len(blob)

    return json.dumps({
        "type": "walk",
        "length": buf.size(),
        "entries": data
    },
                      indent=2,
                      ensure_ascii=False)


def main(dev=False):
    global has_tqdm, args

    if sys.platform == "linux":
        import traceback
        import signal

        def print_stacktrace(sig, frame):
            print("Current stacktrace:\n" +
                  "".join(traceback.format_stack(frame)),
                  file=sys.stderr)

        signal.signal(signal.SIGUSR1, print_stacktrace)

        if len(sys.argv) == 2 and sys.argv[1] == "--dev":
            if sys.platform != "linux":
                print("This only works on Linux.")
                exit(1)

            if not os.path.isdir(os.path.expanduser("~/ruminant")):
                print("Please clone the repo to ~/ruminant first.")
                exit(1)

            if dev:
                print("Installed already.")
                exit(1)

            with open(os.path.expanduser("~/.local/bin/ruminant"), "w") as f:
                f.write(
                    "#!/usr/bin/env python3\nimport sys,os;sys.path.insert(0,os.path.expanduser(\"~/ruminant\"));from ruminant.main import main;sys.exit(main(True))"
                )

            print("Installed dev version of ruminant.")
            exit(0)

    parser = argparse.ArgumentParser(description="Ruminant parser")

    parser.add_argument("file",
                        default="-",
                        nargs="?",
                        help="File to parse (default: -)")

    parser.add_argument(
        "--extract",
        "-e",
        nargs=2,
        metavar=("ID", "FILE"),
        action="append",
        help="Extract blob with given ID to FILE (can be repeated)")

    parser.add_argument(
        "--walk",
        "-w",
        action="store_true",
        help="Walk the file binwalk-style and look for parsable data")

    parser.add_argument("--extract-all",
                        action="store_true",
                        help="Extract all blobs to blobs/{id}.bin")

    parser.add_argument("--filename-regex",
                        default=".*",
                        nargs="?",
                        help="Filename regex for directory mode")

    has_tqdm = True
    try:
        import tqdm
    except Exception:
        has_tqdm = False

    if has_tqdm:
        parser.add_argument("--progress",
                            "-p",
                            action="store_true",
                            help="Print progress")

        parser.add_argument("--progress-names",
                            action="store_true",
                            help="Print filenames in the progress bar")

    args = parser.parse_args()

    if has_tqdm:
        has_tqdm = args.progress
        print_filenames = args.progress_names

    if args.file == "-":
        args.file = "/dev/stdin"

    if args.extract_all:
        modules.extract_all = True
        if not os.path.isdir("blobs"):
            os.mkdir("blobs")

    if args.extract is not None:
        for k, v in args.extract:
            try:
                modules.to_extract.append((int(k), v))
            except ValueError:
                print(f"Cannot parse blob ID {k}", file=sys.stderr)
                exit(1)

    if args.file == "/dev/stdin":
        file = tempfile.TemporaryFile()

        try:
            fd = open("/dev/stdin", "rb")
        except Exception:
            fd = open(sys.stdin.fileno(), "rb", closefd=False)

        with fd:
            while True:
                blob = fd.read(1 << 24)
                if len(blob) == 0:
                    break

                file.write(blob)

        file.seek(0)
        with file:
            print(process(file, args.walk))
    else:
        if os.path.isdir(args.file):
            print("{\n  \"type\": \"directory\",\n  \"files\": [")

            filename_regex = re.compile(args.filename_regex)

            if has_tqdm:
                paths = []
                for root, _, files in os.walk(args.file):
                    for file in files:
                        file = os.path.join(root, file)

                        if filename_regex.match(file) is None:
                            continue

                        paths.append(file)

                paths = tqdm.tqdm(paths)
            else:
                paths = walk_helper(args.file, filename_regex)

            first = True
            for file in paths:
                if has_tqdm and print_filenames:
                    paths.set_postfix_str(os.path.basename(file))

                try:
                    with open(file, "rb") as fd:
                        if first:
                            first = False
                        else:
                            print(",")

                        print(
                            f"    {{\n      \"path\": {json.dumps(file)},\n      \"data\": {{"
                        )

                        print("\n".join([
                            "      " + x
                            for x in process(fd, args.walk).split("\n")[1:-1]
                        ]))

                        print("      }\n    }", end="")
                except Exception:
                    pass

            print("\n  ]\n}")

        elif os.path.isfile(args.file):
            with open(args.file, "rb") as file:
                print(process(file, args.walk))
        else:
            print("File not found.", file=sys.stderr)
            exit(1)
