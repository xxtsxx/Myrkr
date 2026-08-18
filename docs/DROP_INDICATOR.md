# A drop indicator, and dropping into a folder

**Status: COMPLETE.** The insertion line points at a folder row and the dropped
file really lands **inside that folder** — the decision taken 2026-08-09,
built.

| step | what | state |
|---|---|---|
| 1 | `IDropTarget`, `Drop` doing what `wp_dropfiles` did | **done (1.0.18), tested** — `tests/droptest.ps1` |
| 2 | the destination prefix (`g_add_prefix`), selected-row rule | **done, tested** — `tests/prefixtest.ps1` |
| 3 | `DragOver` hit-testing and the line | **done, tested** — `tests/droplinetest.ps1` |

**One rule, two ways of asking it.** A **folder** means inside it; a **file**
means the folder that file is in; **neither** means the archive root. What
changes between the surfaces is only where the row comes from:

- the **buttons** take it from the selection (first selection wins — a
  multi-selection has no single answer, and choosing one beats a button that
  sometimes does nothing);
- a **drag** takes it from the row under the cursor, hit-tested afresh in
  `Drop` rather than carried over from the last `DragOver`, because the cursor
  at the moment of release is the authoritative one.

`g_add_row_set` is the whole handshake: zero — which is what `.data?` starts as
— means "no drag chose anything, use the selection". So the buttons need no
special case, and a row from one drag cannot survive into the next append.

Step 1 landed the payoff §4 predicted: **the drop path is verified for the first
time**, on both the container view and the encrypt view, and the encrypt view's
drop had been shipping untested for years. See `docs/UI_SURFACES.md`.

Two things worth keeping from building it:

- **`POINTL` is passed by value.** It is two `LONG`s, so it goes in `r9` packed
  — x in the low dword, y in the high — which pushes `pdwEffect` out to the
  fifth argument at `[rbp+48]`. Reading it from `r9`, which the argument list
  invites, hands the effect writer a pair of screen coordinates to store
  through. Step 3 unpacks that same `r9` to get the cursor position.
- **`FORMATETC` is not laid out the way the header reads.** `cfFormat` is a
  `WORD` followed by a pointer, so the struct is 8-aligned and `dwAspect` is at
  +16, not +2. Getting it wrong fails `GetData` with `DV_E_FORMATETC` and
  nothing else.

`DragAcceptFiles` is still installed. The plan says to remove it once step 1 is
proven — it now is, but nothing except a *posted* `WM_DROPFILES` can reach it
(the shell finds the OLE target first), and the in-process tests are what post
it. Removing it is its own change.

## 1. Why `WM_DROPFILES` cannot do this

`DragAcceptFiles` gives exactly one message, at the moment of the drop. There is
no drag-*over* notification at all, so there is nothing to paint a moving line
from. `grep RegisterDragDrop src/gui.asm` returns nothing today.

The line requires the window to be a real OLE drop target:
`OleInitialize` + `RegisterDragDrop(hwnd, pIDropTarget)`, with

| method | what it does here |
|---|---|
| `DragEnter` | check the data object offers `CF_HDROP`; set the effect to COPY or NONE |
| `DragOver` | **hit-test the row under the cursor, work out the target folder, move the line** |
| `DragLeave` | erase the line |
| `Drop` | pull `CF_HDROP` out, collect the paths, run the append with the destination |

`DragEnter`/`DragOver` return the effect, which is also what makes the cursor
show copy-vs-refused — feedback the current code cannot give either.

**There is a working template in this tree.** `shellext.asm` already implements
`IShellExtInit` and `IContextMenu` as hand-written vtables with `IUnknown` and
ref counting, inside a DLL loaded into Explorer. Follow its shape exactly:
static vtable, `QueryInterface`/`AddRef`/`Release`, and its note about not using
`FRAME_PROLOG` in code the shell calls does **not** apply here (this object lives
in the exe, which has the canary and shadow stack), so these methods can and
should be framed normally.

## 2. Where the line goes

The container list is the same `SysListView32` the rest of the view uses, and
`LVM_HITTEST` is already wired — `g_lhit` is an `LVHITTESTINFO` the scrollbar
code fills. `DragOver` gets screen coordinates, so `ScreenToClient` then
`LVM_HITTEST` gives the row.

Rules worth settling before writing the paint code:

- Over a **folder row** → the line goes just under that row, indented to the
  folder's depth; the destination is that folder's path.
- Over a **file row** → the destination is that file's *parent* folder; the line
  goes under the parent's last child, not under the file. Dropping "next to" a
  file means "into the folder it is in".
- Over **empty space below the tree** → the archive root.
- The line must be erased on `DragLeave` **and** on `Drop`, and a drag that
  leaves the window without dropping must not leave one behind.

**As built, after two corrections.** The line goes under the destination
folder's own row, at a fixed left edge, and **the archive root draws no line**.

1. The first version anchored the file case on the parent's last visible
   descendant, so hovering a folder and hovering a file inside it drew one
   identical line. `tests/droplinetest.ps1` case 2 rejected it: with the tree
   `top.txt / docs / a.txt / sub`, "inside docs" and "the archive root" both
   anchor on the last row and draw the **same line** — two destinations, one
   picture.
2. The indent went next, on the report that it was wrong and unnecessary. It
   was there to say "inside this rather than next to it", and it does not earn
   the arithmetic: the row the line sits under already says which folder, and
   where an entry lands in the listing is decided by archive order on the next
   refresh. That removed the last thing distinguishing a root line at the
   bottom of the list from "inside the folder on the last row" — hence no line
   for the root, which is the clearer statement anyway. The indicator points at
   a folder; no folder, nothing to point at.

Which is a fair record for a rule written down before anything was drawn.

## 7. The one that got past every test

Dropping into a **collapsed** folder put the entry in the archive and changed
the tree by nothing — not on the reload, not on reopening, because the folder
was still shut. Reported from real use.

`container_load` seeds the top level only. That is right for opening an archive
and wrong straight after an add, so `container_expand_prefix` opens the
destination and its ancestors first, reading `g_add_prefix` (which still holds
the destination at that point — only the next append overwrites it).

Worth naming why nothing caught it: **every test added at the root, or into a
folder that load-time expansion had already opened.** The fixtures all had one
level of nesting, so "the destination folder" and "a folder that happens to be
open" were the same set. `droplinetest.ps1` case 5 now drops one level deeper
and asserts both halves — in the archive, *and* visible.

## 3. The destination, which is the half that changes behaviour

Today a dropped or picked file lands at the archive root: `pack_input_top` takes
the leaf of the source path into `g_rel`, and `zip_input_top` does the same into
`g_zrel`. So the entry name is the leaf and nothing else.

Adding a destination is one global — call it `g_add_prefix`, a UTF-8 archive
path or empty — prepended where those two procs build the name. `a/docs/` plus
`report.pdf` gives `a/docs/report.pdf`, which is exactly what the tree already
displays, so nothing downstream needs to learn a new shape.

**Correction to something said while deciding this:** the `.mrk` side is *not*
harder than the zip side. An entry's AAD is `header || ordinal` — the name is not
in it. The name lives in the index, which is authenticated as a whole, so a
longer name is no different from a shorter one. Both formats need the same
one-line change in the same place. Do them together.

**The prefix is untrusted input the moment it exists.** It comes from a row the
user hovered, so it is ours — but it is concatenated into an entry name, and
`sanitize_name` is what stops `..` and absolute paths from escaping on
extraction. Run the *combined* name through it, not the leaf alone.

**Built, and it earned its place.** A zip whose central directory names
`../escape/x.txt` really does produce a selectable `..` row in the container
view — the reader does not drop it — so the destination genuinely can carry a
traversal. `pack_input_top` and `zip_input_top` run `sanitize_name` on the
combined name and fail the add, which rolls back to the original bytes.
`tests/prefixtest.ps1` crafts that zip and asserts the archive is *unchanged*,
not merely that no `..` was written: checking only for the traversing name
would pass just as happily if the prefix were silently dropped and the file
landed at the root.

The check runs **only when a prefix is set**. A prefix-free add is then
byte-for-byte the operation that shipped before, rather than a new rule applied
retroactively to names that have always been accepted.

## 4. What this unblocks — settled

The drop path had never been verified (see `docs/UI_SURFACES.md`): a synthetic
`WM_DROPFILES` cannot reach the window, and an OLE `DoDragDrop` hung because
`QueryContinueDrag` is only called on mouse input.

Registering a real `IDropTarget` **made it testable**, because the test can call
`DragEnter`/`DragOver`/`Drop` on the interface directly — no drag loop, no
cursor, no UIPI. This turned out to be the whole answer, and the missing piece
was where to get a real `IDataObject`: **the clipboard**. `OleGetClipboard`
returns a genuine system one carrying `CF_HDROP` whenever anything has copied
files, which a test arranges from outside the process in one line. `tests/
droptest.ps1` posts a test-build-only `WM_APP+3`, and the window runs the whole
sequence against it — through the vtable, so a slot in the wrong order fails
rather than passes.

## 5. Order to build it

1. ~~`IDropTarget` with `Drop` doing exactly what `wp_dropfiles` does now, no
   line and no destination. Prove it by calling the interface directly; the drop
   path becomes verified for the first time.~~ **Done in 1.0.18.**
2. ~~The destination prefix, tested through the *buttons* first — no drag
   involved.~~ **Done.** It got its own test rather than an extension of
   `pickertest.ps1`: driving the picker needs `SendKeys`, and the drop hook
   from step 1 sets a selection and adds a file with no modal dialog at all.
   Six cases — three rules × two formats — plus the hostile-prefix case below.
3. ~~`DragOver` hit-testing and the line, last.~~ **Done.**
   `container_prefix_from_row` was split out of the selection walk, so the
   naming rule underneath did not move at all — step 3 only changed where the
   row comes from.

## 6. What the line is checked against

Painting is the one thing no amount of state inspection can confirm: `g_dl_show`
says what the program *intended*. So `tests/droplinetest.ps1` reads the pixels
back out of the listview's own DC and counts accent-coloured ones — client-area
`GetDC`, not `PrintWindow` over non-client, which is a different thing and a
known dead end here.

Four cases: the line appears while a drag hovers and is gone after the drop;
it *moves* between two different destinations (this is the one that caught the
anchor bug); the destination follows the cursor and not the selection; and a
drop off the rows lands at the root.

The third is the case that matters, and it only means something because the
selected row is deliberately set to one whose rule gives a **different** answer
from the hovered row. Steps 2 and 3 are indistinguishable when the two agree.

Step 3 also invalidated the way `prefixtest.ps1` drove its adds. It used the
drop hook, which was quicker; a drop now decides its own destination and
deliberately ignores the selection, so it was testing the selection rule
through a surface that no longer consults it. It drives the **buttons** now,
which is what this plan said before that shortcut was taken.

Keep `DragAcceptFiles` until step 1 is proven, then remove it — two drop
mechanisms on one window is a race nobody needs to debug.
