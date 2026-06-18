#!/usr/bin/env python3

import pathlib
import re
import sys


FORBIDDEN = {
    "kernel pager or swap dependency": [
        r"\buserfaultfd\b",
        r"\bswapon\b",
        r"\bswapoff\b",
    ],
    "cgroup control or system-control dependency": [
        r"/proc/sys",
        r"cgroup\.procs",
        r"cgroup\.subtree_control",
        r"cgroup\.threads",
    ],
    "root or capability dependency": [
        r"\bcapget\b",
        r"\bcapset\b",
        r"\bsetuid\b",
        r"\bseteuid\b",
        r"\bsetgid\b",
        r"\bsetegid\b",
        r"\bmount\s*\(",
        r"\bumount\b",
        r"\bunshare\s*\(",
        r"\binit_module\b",
        r"\bfinit_module\b",
        r"\bdelete_module\b",
    ],
    "kernel-version gate": [
        r"\buname\s*\(",
        r"\bLINUX_VERSION_CODE\b",
        r"\bKERNEL_VERSION\s*\(",
    ],
}


def main():
    if len(sys.argv) < 2:
        print("usage: source_policy_test.py <path> [<path> ...]", file=sys.stderr)
        return 2

    failures = []
    for root_arg in sys.argv[1:]:
        root = pathlib.Path(root_arg)
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in {".c", ".h", ".cpp", ".hpp"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for group, patterns in FORBIDDEN.items():
                for pattern in patterns:
                    match = re.search(pattern, text)
                    if match:
                        failures.append(f"{path}: forbidden {group}: {match.group(0)}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
