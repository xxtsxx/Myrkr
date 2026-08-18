#!/usr/bin/env python3
"""floors - refuse to let a static gate go quiet.

Every checker in tools/ prints how much it inspected, and nothing cares if that
number collapses.  A checker that stops finding things and a checker that stops
LOOKING print the same word: clean.  The second is worse than having no checker
at all, because the green line is counted as evidence.

So each tool declares what it inspected, and this refuses the build if the
number drops below a floor recorded here.  The floors sit in ONE file on
purpose: lowering one is then a visible, reviewable line in a diff, rather than
a constant edited inside a tool nobody re-reads.

Floors are set around 90% of the count at the time of writing - low enough that
ordinary refactoring does not trip them, high enough that a checker losing half
its reach cannot pass.  Raise them when a count grows a lot; lower them only
with a reason in the commit message.

(Ported from Vordr, which added it after two checkers silently lost their
reach - one of them only noticed after a live install went wrong.)
"""

FLOORS = {
    "framecheck": {
        # FRAME_PROLOG procs whose frame was actually sized and checked.
        "procs": 135,                    # 153 at time of writing
        # RAW procs (push rbp / sub rsp,N) given the same spill-overlap
        # analysis.  Floored separately because they are nearly all of gui.asm,
        # and the summary line used to report only the count above - which read
        # as "gui.asm is not covered" to at least one person reviewing it.
        "raw": 115,                      # 128 measured (99 of them in gui.asm)
    },
    "wincallcheck": {
        # WINCALL sites whose argument list was parsed and checked for reads of
        # a register the macro has already overwritten.
        "sites": 700,                    # 791 measured
    },
    "constcheck": {
        # constants deliberately mirrored across modules and compared.
        "mirrored": 18,                  # 20 measured
        "files": 24,                     # 26 sources incl. macros.inc
    },
    "deadcode": {
        "symbols": 1290,                 # 1435 measured (was 1226 before shellext.asm)
    },
    "aligncheck": {
        "scalars": 48,                   # 53 measured
    },
    "wstrcheck": {
        # call sites whose bound-carrying register was checked.  Nearly doubled
        # when wapp_lim joined wcopy in the CONTRACTS table, so the old floor of
        # 15 would no longer notice this checker losing half its reach.
        "calls": 28,                     # 32 measured
    },
}


def check(tool, metrics):
    """Report any metric that has fallen through its floor.

    metrics: {name: count} measured by the caller this run.
    Returns the number of floors breached (0 = fine), so a caller can fold it
    into its exit code and fail a strict build through the path it already has.
    """
    floors = FLOORS.get(tool)
    if floors is None:
        return 0
    breached = 0
    for name, minimum in sorted(floors.items()):
        got = metrics.get(name)
        if got is None:
            print(f"[FLOOR] {tool}: no longer reports '{name}' - either the metric was "
                  f"renamed or the check was removed; update tools/floors.py deliberately")
            breached += 1
            continue
        if got < minimum:
            print(f"[FLOOR] {tool}: only {name}={got}, floor is {minimum} - this checker "
                  f"has gone quiet.  Either it lost its reach (a bug in the tool, or an "
                  f"idiom it no longer recognises) or the codebase really shrank; if the "
                  f"latter, lower the floor in tools/floors.py and say why.")
            breached += 1
    return breached


def _cli():
    """Command line, so a checker that is not written in Python can use the same
    floors.  The point of this file is that floors live in ONE place; a tool in
    another language having its own copy would defeat that.

        python tools/floors.py wincallcheck sites=791

    Exits non-zero if any named metric is under its floor.
    """
    import sys
    if len(sys.argv) < 3:
        print("usage: floors.py <tool> name=count [name=count ...]")
        return 2
    tool = sys.argv[1]
    metrics = {}
    for arg in sys.argv[2:]:
        name, _, count = arg.partition('=')
        try:
            metrics[name] = int(count)
        except ValueError:
            print(f"[FLOOR] {tool}: '{arg}' is not name=count")
            return 2
    return 1 if check(tool, metrics) else 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
