"""
vtest sandbox entrypoint (baked into localhost/vtest-pytest:1, never controlled by the repo).

Reads a tar stream from stdin into /work (a tmpfs), then:

  (no args) | pytest     run the generated tests in /work/test_generated.py
  app -- CMD [ARGS...]   exec the target application command (stress agent)

Extraction uses tarfile's "data" filter, which rejects absolute paths,
'..' traversal, links, device files and setuid bits.
"""

import os
import sys
import tarfile

WORK = "/work"


def _extract() -> None:
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tar:
        tar.extractall(WORK, filter="data")
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)


def _run_pytest() -> None:
    ini = os.path.join(WORK, "pytest.ini")
    # Written after extraction, so the payload cannot supply its own config.
    with open(ini, "w") as f:
        f.write("[pytest]\n")
    os.execvp(sys.executable, [
        sys.executable, "-m", "pytest", "test_generated.py",
        "-c", ini, "--rootdir", WORK, "--confcutdir", WORK,
        "-p", "no:cacheprovider", "-v", "--tb=short", "--no-header",
    ])


def main(argv: list[str]) -> int:
    mode = argv[0] if argv else "pytest"
    if mode not in ("pytest", "app"):
        print(f"vtest-entrypoint: unknown mode {mode!r}", file=sys.stderr)
        return 64
    if mode == "app" and (len(argv) < 3 or argv[1] != "--"):
        print("vtest-entrypoint: usage: app -- CMD [ARGS...]", file=sys.stderr)
        return 64

    _extract()
    os.chdir(WORK)

    if mode == "pytest":
        _run_pytest()
    else:
        os.execvp(argv[2], argv[2:])
    return 70  # unreachable: exec does not return


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
