# A progress bar for removals

**Status: BUILT for `.mrk`. The zip removal still has no bar.**
`do_remove_marked` totals its work exactly and `tests/rmbartest.ps1` proves it:
`g_prog_done` equals `g_prog_total` to the byte after a real removal.
`zip_delete_marked` is unchanged — §2 says why a total for it would be an
estimate, and `enter_running` still hides the bar when `g_is_zip` is set, so no
bar ever shows a number it cannot stand behind.

The plan as written, kept because §2's arithmetic is the whole of it: Adds got a real bar in 1.0.14; removals still
show nothing, so a large one looks like the window has simply stopped.

Not started because the two procs it instruments — `do_remove_marked` and
`zip_delete_marked` — are the two that destroy data, and the session that would
have written this had no budget left to test them. Instrumentation is additive
and low-risk, but "low-risk and untested" on the delete path is not a thing to
hand over.

## 1. Neither path reports anything today

`grep progress_add` finds nothing in either. This is not a matter of calling
`progress_begin` and having a bar appear — both write loops need
`progress_add` calls adding to them as well.

## 2. The total is the actual problem

The obvious total — sum of `IDXE_stored` over every entry — over-reports, and a
bar that stalls at 85% and then jumps is worse than no bar.

`do_remove_marked` does two passes and only some bytes move:

- **wipe**: every entry marked `IDXEF_DROPPED`, `IDXE_stored` bytes each. All of
  these are written.
- **compact**: survivors slide down over the holes. A survivor *before the first
  hole* does not move at all — its destination equals its source, and the loop
  skips it. Only survivors after the first dropped entry are copied.

So the honest total is:

```
sum(stored) over dropped entries
  + sum(stored) over survivors whose offset > the first dropped entry's offset
```

Both are available in the walk `dw_entry` already does; it needs one extra
accumulator and the offset of the first dropped entry. Compute it before the
wipe pass starts and pass it to `progress_begin` with `lbl_pack`.

`zip_delete_marked` is simpler: it copies survivors to a new file, so the total
is the sum of the survivors' local-header-to-data extents — the same figure its
survey pass already computes to size the output.

**Do not paper over a wrong total by forcing the bar to 100% at the end.**
`on_done`'s crypto path does that for a different reason (a fast job where the
100 ms timer never ticked). Using it to hide arithmetic that was never right
just moves the lie to the last frame.

## 3. Cancel stays off

Unchanged from `CONTAINER_EDITS_THREADING.md` §5, and the reasoning is not
affected by adding a bar: `do_remove_marked` overwrites entries in place and
`zip_delete_marked` rewrites the archive, so stopping either half way leaves
work that would have to be explained rather than undone. A bar tells the user
how long to wait; it does not make the operation interruptible.

## 4. The one UI change

`enter_running` currently hides the bar for `g_wt_job = 2`. That check becomes
"hide it for nothing" once both removal paths report — but leave the Cancel
half of that branch exactly as it is.

## 5. How to know it worked

- `tests/rmbartest.ps1` is this section, landed: it drives a `.mrk` removal
  through the GUI, samples `g_prog_pct` out of the process, asserts the bar is
  monotonic, asserts `g_prog_done == g_prog_total` at the end, and checks the
  container still authenticates afterwards. (Two session-local scripts -
  `v6del.ps1` and a zip twin - used to be named here; they no longer exist,
  and the zip removal path is covered by the rewrite checks in
  `tests/extracttest.ps1`.)
- For the bar, the check that matters is that it is **monotonic and ends at
  100% without being forced there**. Sample `g_prog_pct` out of the process
  (`tests/threadtest.ps1` shows the ReadProcessMemory pattern) across a removal
  from a large archive, and assert it never goes backwards and its last value
  before `WM_APP_DONE` is 100.
