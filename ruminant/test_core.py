from . import tests as ts
import traceback


def main():
    test_counts = sum([len(x) for x in ts.tests.values()])
    success = 0
    failures = {}
    print(f"Found {test_counts} test{'' if test_counts == 1 else 's'}")

    ig = 1
    jg = len(ts.tests)
    for group, tests in ts.tests.items():
        print(f"\033[0;30;47mGroup {group} [{ig}/{jg}]\033[0m")
        ig += 1

        it = 1
        jt = len(tests)
        for name, test in tests.items():
            print(f"Test {name} [{it}/{jt}] ... ", end="")
            it += 1

            try:
                test()

                print("\033[92msuccess\033[0m")
                success += 1
            except Exception:
                print("\033[91mfailed\033[0m")
                print("Error was:")
                traceback.print_exc()

                if group not in failures:
                    failures[group] = []

                failures[group].append(name)

    print(f"\033[0;30;47mSummary: [{success}/{test_counts}]\033[0m")
    if success != test_counts:
        print("Failed tests:")

        for group, names in failures.items():
            print(f"  {group}: {', '.join(names)}")

    print("Done, bye :)")
    exit(0)
