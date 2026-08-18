# What the window is after an encrypt finishes

**Status: FIXED.** Reported 2026-08-09 as "drag and drop to add files to a new
encrypted file — the added content isn't saved". `switch_to_output` now makes
the window become the file it just made; `tests/afterencrypttest.ps1` drives
the reported flow end to end and reads the archive back with the CLI.

**Superseded for the right-drag itself, 2026-08-12.** The question below — what
the window *becomes* after a right-drag encrypt — stopped being the right
question. A right-drag now gets no main window at all: it gets the small
progress window, and on success it closes. See §5. The answer here still governs
the double-click path, which is the one where you go on working in the window.

The test carries three traps worth keeping:

- **It asserts the "Saved to…" box is ABSENT.** It used to dismiss it: `on_done`
  blocked inside that modal until someone clicked OK, so a test that skipped it
  never reached the code under test and faithfully reported the *old* behaviour.
  That cost a full round. The box was removed in 1.0.39, so the trap is now
  inverted — a modal reappearing on this path blocks the view switch again.
- **It reads the archive with the CLI**, which owes nothing to the window. The
  row count going up is exactly the symptom that made the bug convincing in the
  first place.
- **It reads the details panel with `WM_GETTEXT`, not `GetWindowTextW`.**
  Cross-process, `GetWindowTextW` does not send `WM_GETTEXT`; it returns the
  string USER32 cached from `CreateWindow`. An EDIT keeps its text in its own
  buffer, so one whose contents have been replaced still reads back as its
  creation placeholder. That is a third instance of the same failure — the
  harness agreeing with itself — and it cost a long hunt for a bug in code that
  was working.

## 1. What actually happens

Reproduced exactly, driving the shell extension's own invocation
(`myrkr.exe <folder> --to <dir>`):

```
main window: title='Myrkr - encrypt'   action='Encrypt'
produced: folder.mrk
list rows: 1  ->  after drop: 2        status: "3 files, 34 B"
archive contents:  folder\one.txt
                   folder\two.txt      <- the dropped file is not there
```

When an encrypt completes, `on_done` takes the `od_restore` path: it hides the
progress bar, re-enables the controls, clears the password fields and sets the
status to Ready. **It does not change what the window is.** The title still says
encrypt, the action button still says Encrypt, and the list is still the INPUT
list.

So a drop after a completed encrypt adds another *input*, for an encryption that
never runs again. The status line updates - "3 files, 34 B" - which makes it
look as though something was taken in. The archive on disk is untouched.

Nothing is lost: the file was never added. But the screen implies it was, which
is the same shape as the silent refusal fixed in 1.0.16 and worse than an error
would be.

## 2. Why the report said "close the encrypted file"

Because that is a reasonable reading of the window. The user encrypted
something, is looking at a window that names it, and treats it as the open
document. Every gesture after that - drop to add, Exit to close - follows from
that model, and the program does not contradict it until the file is reopened.

## 3. The fix worth making

**Switch to the container view of the file just produced.** Then the window is
what it appears to be: drops append to the archive (that path already works and
is tested), Exit closes the archive, and reopening shows what was added.

`container_load` already does the work. Two things to get right:

- **The password.** `od_restore` wipes `g_cfg_pass`, and `od_container` exists
  precisely because the container view has to keep it for the window's life.
  Switching after an encrypt means taking the `od_container` path instead, or
  it will prompt for a password the user just typed twice.
- **The output path.** `g_cfg_out` holds what was written; the container view
  expects `g_filepath_w`. One is a copy of the other, but they are different
  globals and `container_load` reads the second.

Alternatives considered and rejected:

- *Refuse drops after a completed encrypt.* Honest but useless: it tells the
  user what they cannot do rather than doing the obvious thing.
- *Relabel the action "Encrypt again".* Removes the ambiguity without removing
  the extra step, and leaves the list meaning something different from what a
  user who just encrypted expects.

## 4. What was fixed already, and was NOT this

1.0.22 fixed a genuine defect found while chasing this - an encrypt-view drop
started a second indexer pass over the same inputs, so the status read "6 files"
for three. That was real, and it was not the cause of this report. Worth
recording, because the count being wrong looked like an explanation and was not
one.

## 5. And then the question changed

Reported 2026-08-11, after the fix above had shipped: leaving *any* window up
after a right-drag encrypt "begs you to add/modify the contents further, and you
can't". The window was correct — it really was the container, and a drop really
did reach the archive — and it was still the wrong thing to be looking at. A
right-drag is a gesture that asks for one thing to happen. It is not a request
to open an editor.

So the right-drag no longer opens the main window at all. It gets a small
progress window — heading, destination, a bar, the file being worked on, and a
count — with the log folded away behind a Details button, in the shape of the
Windows copy dialog. Then:

- **Success closes everything.** The thing that was asked for happened; there is
  nothing left to look at, and no window to dismiss.
- **A failure halts there** with the details already folded out and the error at
  the bottom of them. That is the one moment the log is the point, so it is the
  one moment the window stays.

`switch_to_output` and everything in §1–§3 still describe the double-click path,
which is unchanged: open a container and you get a window you can work in.

Both ends are asserted in `tests/afterencrypttest.ps1` — the failure end forced
by pointing `--to` at a file, so the output cannot be created.

## 6. The colour follows the state — and what that uncovered

Asked for on 2026-08-12: bring back the accent bar down the left margin, and let
the colour say which state the window is in. Both are small; getting them to
show up was not.

The window now computes one colour per paint — accent while it works, invalid
red when it stops on an error, warning amber when the user cancelled — and the
stripe, the frame, the heading and the bar all take it from there. Three states
because three are all it can be *seen* in: a success destroys the window, so a
green would be pixels nobody can look at.

Making that visible turned up three real defects, in the order they surfaced:

1. **The backdrop was 300px taller than the window.** It was created at the
   tallest state it could reach so it would never need resizing, and
   `hairline_rect` draws round the rect it is given — so the collapsed window's
   bottom edge and both bottom corners were drawn below the visible client and
   the frame hung open at the bottom. It sizes with the window now.
2. **The repaint was aimed at the window, not at the backdrop.** A child
   repaints when its *own* region is dirty; invalidating its parent does
   nothing. So the backdrop never repainted after its first frame: on a failure
   the window went on saying "Encrypting" in accent blue, and the bar and the
   file count sat frozen for the entire job. Nobody had noticed, because until
   the colour changed there was nothing on that surface that visibly *should*
   have moved.
3. **And the backdrop was at the TOP of the z-order.** Which is why (2) had
   stayed invisible rather than merely wrong: the first thing a correct repaint
   did was paint over Details, Close, the log and its buttons, and nothing
   invalidates those afterwards. `WS_CLIPSIBLINGS` cannot help a window with
   nothing above it. It goes to `HWND_BOTTOM` now — restated on every expand,
   not just at creation, because controls created later land *below* it.

The test asserts (3) directly, since it is the root cause and needs no screen:
`EnumChildWindows` enumerates top-first, so the backdrop's id must come last.
Run against the unfixed build the z-order reads `191 104 190 193 195 194` — the
backdrop sitting above the log it is about to erase.

The colours themselves were checked by sampling the screen: `005FB8` down the
left margin while working, `C42B1C` after a failure, each with the frame beside
it at exactly half luminosity. The bar was checked the same way, by watching the
filled width grow — `0 0 0 0 0 0 62 148 225 321` pixels, the leading zeros being
Argon2 before any file is touched.

The one thing deliberately left alone is the primary button, which stays accent
blue on a failure. A red **Close** reads as a destructive action, and closing a
window that has already failed destroys nothing.
