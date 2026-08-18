# Moving the container edits onto the worker thread

**Status: BUILT.** `tests/threadtest.ps1` measures it: the window answers every
`SendMessageTimeout(WM_NULL)` across a full 480 MB append, and the test fails if
fewer than 15 pings land inside the append window, so it cannot pass by being
too quick to observe. An **add** shows the progress bar and an
enabled Cancel, both wired and both tested (`tests/canceltest.ps1`). A
**removal** still shows neither, deliberately: `do_remove_marked` overwrites
entries in place and `zip_delete_marked` rewrites the archive, so stopping
either half way leaves work that would have to be explained rather than simply
undone. A Cancel that cannot cleanly undo is worse than no Cancel.

The original plan, kept because the traps it names are all still live: `container_add` and `container_remove_selected`
run on the UI thread, so a large add or removal freezes the window. Encrypt and
decrypt already run on a worker; these two need to join it.

Written down rather than started because the change splits both procs three ways
and threads a new job selector through `worker_thread`, `enter_running` and
`on_done` — the three procs that decide what the window is doing. A half-applied
version leaves the GUI in a state where the difference between "working" and
"wedged" is invisible.

## 1. What is already there

```
enter_running    UI transition: disable inputs, show progress, start the 100ms
                 timer, CreateThread(worker_thread)
worker_thread    sstk_thread_init, dispatch on g_op / g_make_zip / g_is_zip,
                 g_op_result = eax, PostMessage(WM_APP_DONE), sstk_thread_free
on_done          WM_APP_DONE: report, restore the UI
```

`worker_thread` is the sole user of the software shadow stack while active and
calls `sstk_thread_init` itself — that is not optional and not shared. See the
comment on it, and the fastfail it records.

## 2. The split

Neither container proc can move wholesale. Each has parts that *must* stay on
the UI thread:

| stays on the UI thread | why |
|---|---|
| the file picker (`add_via_picker`) | COM STA dialog, owned by the window |
| `container_mark_selected` | reads the listview |
| `confirm_slow_remove` | modal dialog |
| `idx_read` for the remove path | today it runs before marking, and marking needs the index |
| `container_load` | repaints the listview |
| the failure `mbox` | modal |

What moves is only the middle: `do_add` / `do_zip_add` / `do_remove_marked` /
`zip_delete_marked`.

## 3. The job selector

```
g_wt_job    dd ?     ; 0 = crypto (today), 1 = container add, 2 = container remove
```

`worker_thread` branches on it before anything else. Set it in the UI-side prep,
immediately before `enter_running`; reset it to 0 in `on_done`, so a later
Encrypt cannot inherit it. **That reset is the whole risk of this change** — a
stale `g_wt_job` sends the action button into an append.

## 4. Each proc becomes three

- `container_add` keeps the picker, the `g_poscount` bookkeeping and the
  `g_cfg_in` setup, then sets `g_wt_job = 1` and calls `enter_running`. It must
  NOT restore `g_poscount` — the worker still needs `g_positionals[]`. That
  moves to `on_done`.
- `container_remove_selected` keeps `idx_read`, the marking and
  `confirm_slow_remove`, then sets `g_wt_job = 2` and calls `enter_running`.
  Its `crs_wipekey` path (nothing selected, or the user cancelled) still wipes
  the key and returns without launching anything.
- `on_done` gains a branch: for jobs 1 and 2, restore `g_poscount`, wipe
  `g_key`, show the failure `mbox` if `g_op_result` is non-zero, then
  `container_load`. The zip-removal path's three-way message
  (`m_zip_io` / `m_zip_norw` / `m_zip_part`) moves here verbatim.

## 5. Traps, in the order they will bite

- **`enter_running` touches controls the container view does not have.** It
  already null-checks `g_hconfirm` and `g_hdest`; `g_hpass` and `g_hstatus` are
  not checked. Verify they are non-null in container mode before reusing it, or
  give it a container-aware path.
- **The cancel button becomes live.** `enter_running` enables it, and
  `g_cancelled` is checked by the crypto paths. `do_remove_marked` and
  `do_zip_add` do not check it, so Cancel would appear to do nothing. Either
  wire it or leave Cancel disabled for these jobs — do not leave a button that
  lies.
- **Progress.** These paths call `progress_add` but never `progress_begin`, so
  `g_prog_total` is 0 and the bar would sit at 100%. `do_zip_add` can total its
  inputs the way `do_zip` does; `do_remove_marked` knows its byte count up
  front.
- **`g_keep_key` and the key lifetime.** The remove path derives the key on the
  UI thread and the worker uses it. That is fine — it is a global — but the
  wipe must move to `on_done` or the key outlives the operation.
- **Re-entrancy.** `g_running` already gates the Add/Remove commands. Confirm
  the container view's command bar honours it, since these commands were
  previously synchronous and could not overlap.

## 6. How to know it worked

`tests/pickertest.ps1` already drives the whole add path end to end and asserts
the archive, the refresh and the process staying alive; it should keep passing
unchanged. Add to it:

- the window still answers `WM_NULL` (SendMessageTimeout) *while* a large add is
  running — that is the actual point of this change and nothing else tests it
- `g_running` returns to 0 afterwards, and a second add works
- an Encrypt straight after a container add still encrypts, which is the
  stale-`g_wt_job` regression

A removal equivalent does not exist yet; `tests/rmbartest.ps1` drives one
through the GUI and samples the progress globals, and is the closest starting
point in the tree.
