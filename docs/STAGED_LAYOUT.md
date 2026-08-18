# Dropping into a folder while BUILDING an archive

**Status: BUILT.** Dropping onto a folder row in the *encrypt* view places the
file **inside that folder in the archive**, without touching the disk. The tree
draws it there too, which was the half that made this worth specifying first.

`tests/stagetest.ps1` covers the naming, `tests/stagedroptest.ps1` the drop and
the tree together — the second asserting that those two AGREE, since either
alone is the bug this doc exists to prevent.

Two things the build taught, both worth more than the code:

- **The tree caught a defect the checkers could not.** `emit_input` stored the
  input path as a qword at `[rbp-32]`, which overlaps the depth dword at
  `[rbp-28]` — a qword at -32 occupies -32..-25. Writing the path silently
  zeroed the depth, so every staged row was emitted at depth 0: drawn at the
  top level while sitting in the middle of the folder it belonged to. It built
  clean, framecheck passed, and the list looked *almost* right. Only asserting
  the drawn x-position found it.
- **The harness lied twice before the product did.** `LVITEM.iIndent` read back
  as 32759 — the top half of a pointer — and `'  ' * 32759` built a 65KB line
  that every output filter then hid; and a one-row `Tree` unrolled to a scalar,
  so indexing it returned characters. Both looked exactly like the feature
  being broken. Depth now comes from the label rect, which is the control's own
  answer about where it drew the text.

## 1. Why this is not the same feature as the container view's

The container view already does it (`docs/DROP_INDICATOR.md`). There, a folder
row is an entry in an index, the destination is a string, and placing something
"inside" it is one prefix on one name.

The encrypt view is a different thing wearing the same clothes. Its rows come
from `rows_build`, which walks `g_positionals[]` and, for each expanded folder,
enumerates the **real filesystem** (`rows_expand_into`). Every row is a path
that exists. The archive layout is derived from those paths and never stored
anywhere: `pack_input_top` takes the leaf of each input, `pack_node` appends
child names as it recurses, and the result is the entry name.

So "drop this file into that folder" has nowhere to be recorded. The tree is a
view of the disk, and the disk is not going to have the file in that folder.

## 2. What has to exist that does not

**A layout that is separate from the paths.** The pending archive stops being
"these paths" and becomes "these paths, at these names". Minimally:

- a per-input destination, parallel to `g_positionals[]` - call it
  `g_pos_prefix[]`, each entry an offset into a small arena, 0 meaning the root;
- `do_pack` and `do_zip` set `g_add_prefix` from `g_pos_prefix[i]` before each
  `pack_input_top` / `zip_input_top` call, instead of leaving it fixed for the
  whole run.

That second part is nearly free, because the prefix machinery already exists and
is already applied in exactly the right place. **The naming half of this feature
is a day's work.** What follows is the rest.

## 3. The part that is not free: the tree has to show it

A file dropped into `docs/` must appear under `docs` in the list, or the feature
has done nothing a user can see - and worse, the archive will not match the tree
they were looking at when they pressed Encrypt.

`rows_expand_into` enumerates a directory. It would also have to emit any input
whose destination is that directory, interleaved with the real children. That
means:

- the row model gains rows that are not filesystem children of their parent;
- `row_path` stops being "the path this row names" for those rows, because two
  different things are now true of them: where the bytes come from, and where
  they go. Several callers assume those are the same string - `pset_add` on
  `g_expanded`, the exclusion set, `container_mark_selected`'s name conversion;
- a virtual folder becomes possible (drop into a folder that exists only in the
  archive), and then there is no path at all to key anything by.

**The sets are the sharp edge.** `g_expanded` and `g_excluded` are keyed by
path, on purpose, because every rebuild renumbers the rows. Virtual placement
introduces rows whose identity is not a path. Either they get synthetic keys
that cannot collide with real ones, or the sets change shape.

## 4. Order to build it

1. ~~**`g_pos_prefix[]` and the per-input prefix in `do_pack`/`do_zip`.**~~
   **Done.** `pfx_stage` / `pfx_select` / `pfx_reset` in `pack.asm`, driven for
   testing by a `--stage <n>:<folder>` option that exists only in a test build.
   `tests/stagetest.ps1` covers both formats, subtree inheritance, the
   unstaged path being unchanged, and a `..` destination being refused.

   Two things worth knowing before step 2 touches it:

   - **`g_pos_prefix[]` is indexed by position, and positions move.**
     `remove_selected` compacts `g_positionals[]`, so it now moves the prefixes
     alongside and clears the slots that fall off the end. Left alone the array
     would not merely be stale - it would name a folder for a file that is now
     somebody else. `clear_inputs` calls `pfx_reset`.
   - **The destination is not validated where it is staged.** `sanitize_name`
     runs on the *combined* name in `pack_input_top` / `zip_input_top`, which
     is the only place the whole string exists. So a traversing destination
     fails the add rather than the staging, which is the same guard
     `docs/DROP_INDICATOR.md` describes reached by another road.
2. **Drop targeting in the encrypt view**, writing `g_pos_prefix[]` from the
   hovered row. The indicator, the hit test and `dest_row_from_hit` are already
   there and already work on this view's row model.
3. **The tree.** Last, and the only genuinely hard part. Do not start it before
   1 and 2 are shipped: if the layout is right in the archive and merely
   invisible in the list, that is a missing feature; if the list shows a layout
   the archive does not produce, that is a lie about what was encrypted.

## 5. What must not happen

- **Nothing may be written to the user's disk.** The rejected alternative was to
  copy the dropped file into the real folder, which is simple and wrong: a drag
  that silently modifies the source tree is not something a user can undo.
- **The tree and the archive must not disagree.** If step 3 is not done, the
  drop should either be refused in the encrypt view or land at the root - the
  behaviour that ships today - rather than land somewhere the list does not
  show.
