# Every action, on every surface

What each format can do, and which of the three surfaces reaches it: the
**buttons** in the window, **drag-and-drop** onto the window, and Explorer's
**right-click / right-drag** through the shell extension.

| action | `.mrk` | `.zip` | buttons | drop on window | Explorer |
|---|---|---|---|---|---|
| create | yes | yes | Encrypt | yes | right-click / right-drag |
| open / browse | yes | yes | — | — | double-click, or "Myrkr decrypt/extract" |
| extract all | yes | yes | Decrypt / Extract | — | yes |
| extract selected | yes | yes | select + Decrypt | — | — |
| **add to an existing archive** | yes | yes | Add files / Add folder | **yes, since 1.0.16 — verified in 1.0.18** | no |
| remove entries | yes | yes | Remove | — | no |

## The gap this closed

Adding to an existing archive landed in 1.0.9–1.0.14 on the buttons only. A drop
onto an open container was **silently ignored** — `wp_dropfiles` refused
anything with `g_op != 0`, which was correct while the container view could only
be read and stopped being correct the moment it could be added to. Two surfaces
for one action have to agree, and the failure mode was the worst kind: nothing
happened and nothing said so.

`wp_dropfiles` now branches on `g_container` first. Browsing an archive means a
drop is an append, and it goes down the same `container_add_run` the Add button
uses — the picker and the drop leave identical state (slot 0 is the archive, the
rest are what to add), which is why the tail is shared rather than duplicated.
Dropping on the *decrypt* dialog is still refused: that view is built around
exactly one container and its destination logic assumes it.

## Not verified — and why a synthetic drop cannot verify it

**The drop-to-append path has not been driven end to end.** It is implemented
and it builds, but nothing has watched it work.

The attempt was a synthetic `WM_DROPFILES`: a `DROPFILES` header plus wide
paths, written into the target with `VirtualAllocEx`, then `PostMessageW`. It
appended nothing. The first guess was that `DragQueryFileW` had rejected the
handle, since it calls `GlobalLock` and that wants an `HGLOBAL`. **That guess
was wrong** — `DragQueryFileW` reads a `VirtualAlloc` HDROP perfectly well; a
two-line test in-process returns the right count and the right path.

The control that settled it: post the identical HDROP to the window in
**encrypt** mode, where the drop path has shipped for many versions and users
rely on it daily. It appended nothing either. So the message is not arriving at
all. `WM_DROPFILES` carries a memory handle and sits on UIPI's cross-process
block list; a posted one from another process is dropped before any window
procedure sees it, whatever the receiving code does.

**A synthetic post therefore cannot verify this path for any build, working or
broken.** Run that control first next time — it costs one launch and it is the
difference between debugging the product and debugging the harness.

### The OLE attempt, and the one thing it got wrong

An OLE drag was tried next and is the right shape: `DoDragDrop` takes the drop
position from the **cursor** and asks `IDropSource::QueryContinueDrag` when to
release, so parking the cursor over the window and returning `DRAGDROP_S_DROP`
should drop there — through the target `DragAcceptFiles` installed, which is the
real path.

It hung. `QueryContinueDrag` is **only called when the drag loop receives mouse
or keyboard input**. With a stationary cursor and no button transitions it is
never called at all, the "drop after N calls" never fires, and `DoDragDrop`
spins modally forever. That approach was abandoned rather than finished:
`tests/droptest.ps1` covers the drop path by registering a real `IDropTarget`
and CALLING it (see the header there), which needs no drag loop at all - a
test that hangs for ten minutes is worse than no test.

Finishing it means generating mouse motion *during* the call, and `DoDragDrop`
is modal on the calling thread — so the motion has to come from a second thread
or a second process:

1. Start the drag on one thread with the cursor already over the target; from
   another, `mouse_event` a few small `MOUSEEVENTF_MOVE` steps so the loop calls
   `QueryContinueDrag`, which then returns `DRAGDROP_S_DROP`. Holding the left
   button down across the whole sequence is closer to a real drag and is worth
   trying first.
2. Or drive a genuine Explorer drag end to end with UI automation, which needs
   no OLE plumbing but does need the source item's screen rect, and modern
   Explorer draws its items with DirectUI rather than a listview.

The shared tail is covered: `tests/pickertest.ps1` exercises
`container_add_run` through the button, and the drop reaches that same proc.
What is untested is the collection step and the branch that selects it.

## Resolved in 1.0.18 — by changing the product, not the test

Every attempt above tried to *deliver* a drag. None of them can, and the reasons
are structural rather than fixable. What finally worked was making the thing
callable: registering a real `IDropTarget` (`docs/DROP_INDICATOR.md` step 1)
means a test can invoke `DragEnter` / `DragOver` / `DragLeave` / `Drop` directly
— no drag loop, no cursor, no UIPI.

The source of a real `IDataObject` is the clipboard. `OleGetClipboard` returns a
genuine system data object carrying `CF_HDROP` the moment anything copies files,
which a test arranges in one line from outside the process. So nothing in
`tests/droptest.ps1` is a mock: the same `GetData`, the same `STGMEDIUM`, the
same `HDROP` walk a shell drag produces. It covers, on both the container view
and the encrypt view:

- the window really is a registered OLE drop target (`GetProp` for
  `OleDropTargetInterface`, read from another process — `g_dt_ok` records what
  ole32 *returned*, the property records what ole32 *did*);
- a data object with no `CF_HDROP` is refused, and refusing runs
  `DragEnter → DragOver → DragLeave` to the end;
- dropped files reach the archive, checked with an independent zip reader, bytes
  compared against the original;
- the encrypt view's drop, which had never been tested either, and which now
  runs through this same code because a real shell drag reaches the registered
  target rather than `WM_DROPFILES`.

**Still not covered:** ole32's own delivery of a drag to a registered target.
That is Microsoft's code between the shell and our vtable, and the registration
check above is as close to it as anything here can get.

## Attempt 4, abandoned — and what it did establish

Tried again with injected input: `DoDragDrop` on an STA thread, `mouse_event`
movement from a second thread to give the drag loop the input it needs. It got
further than the earlier version and still failed, this time with
`QueryContinueDrag` called **zero** times while `DoDragDrop` sat blocked.

Two things were ruled out on the way, and they are the useful part:

- **Injection works.** A probe moved the cursor with `SetCursorPos` and with
  `mouse_event(MOUSEEVENTF_ABSOLUTE)` and read it back at the requested point.
  So "the input never arrives" is not about the injection.
- **It is not the launch context.** Same result through two different shells.

What is left is the real reason, and it is structural in the same way the other
three were: **`DoDragDrop`'s `SetCapture` only takes effect for the foreground
thread.** A test that raises the *target* window so the drop lands on it has,
by that act, made its own process not-foreground — so the mouse messages go to
the window under the cursor, in the other process, and the drag loop never sees
one. The harder the test tries to set the drop up, the more certainly it
prevents it.

Doing it properly means a visible source window of our own, brought to the
foreground, receiving a genuine `WM_LBUTTONDOWN` and starting the drag from its
own `MouseDown` — i.e. building a real drag source application. That is a
plausible next attempt and it was not taken: the cost is a GUI app maintained
as test scaffolding, and what it would add over `droptest.ps1` is confidence in
ole32's own plumbing rather than in any of our code.

If it is ever revisited, start from the foreground requirement — not from the
input injection, which works.

`WM_DROPFILES` stays for now. Nothing but a posted one can reach it any more —
the shell finds the OLE target first — and the in-process tests are what post
it. The plan says to remove it once step 1 is proven; that is a separate change
from proving it.

## Deliberately not wired

- **Explorer has no "add to archive" verb.** It would mean a right-drag onto a
  `.mrk` or `.zip` meaning "append", which collides with the existing drop
  handler's meaning ("encrypt these *to* this folder"). Worth doing, but it is a
  shell-extension design question, not a wiring gap.
- **Remove has no drop surface**, which is as it should be: dragging something
  onto a window is how you add it, not how you take it away.
