from . import tests as ts
import traceback
import os
import sys


# tests main
def main():
    # try to get terminal width so we can display the status on the right
    try:
        width = os.get_terminal_size().columns
        assert width > 40
    except Exception:
        print("\033[0;;41mTerminal is too narrow.", file=sys.stderr)
        exit()

    # get total test count to print it
    test_counts = sum([len(x) for x in ts.tests.values()])
    success = 0
    failures = {}
    print(f"Found {test_counts} test{'' if test_counts == 1 else 's'}")

    # index for group progress report
    ig = 1
    jg = len(ts.tests)
    for group, tests in ts.tests.items():
        print(f"\033[0;30;47mGroup {group} [{ig}/{jg}]\033[0m")
        ig += 1

        # index for test progress report
        it = 1
        jt = len(tests)
        for name, test in tests.items():
            line = f"Test {name} [{it}/{jt}] ... "
            print(line, end="")
            it += 1

            try:
                test()

                print(" " * (width - len(line) - 7), end="")
                print("\033[92msuccess\033[0m")
                success += 1
            except Exception:
                print(" " * (width - len(line) - 6), end="")
                print("\033[91mfailed\033[0m")
                print("Error was:")
                traceback.print_exc()

                # group had no failures so far? add an entry in the failures dict
                if group not in failures:
                    failures[group] = []

                # add failed name
                failures[group].append(name)

    print(f"\033[0;30;47mSummary: [{success}/{test_counts}]\033[0m")

    # print failed names per group
    if success != test_counts:
        print("Failed tests:")

        for group, names in failures.items():
            print(f"  {group}: {', '.join(names)}")

    print("Done, bye :)")
    exit(0)
