# Path limits and archive compatibility

There are two different measurements: the full filesystem path used to open a
file, and its relative name stored inside the archive. Long-path Windows API
support does not remove limits in archive metadata or in other applications.

| Layer | Limit / behavior |
|---|---|
| Windows filesystem paths | Extended-length Unicode paths, beyond legacy `MAX_PATH`. Windows' nominal ceiling is 32,767 UTF-16 units; filesystem component limits still apply. |
| Myrkr source walker | Uses 32,768-unit buffers with a 32,512-unit walk guard. Paths beyond that guard are rejected, not shortened. |
| Myrkr stored relative paths | Writers accept at most **4,094 UTF-8 bytes**, including directory separators, excluding NUL. This applies to native archives and ZIP. |
| Add/drop destination prefix | Separately capped at roughly 3 KiB (`ADDPFX_MAX` = 3,072 bytes including conversion headroom), reserving room for the added leaf. Adding at the root avoids this prefix limit. |
| Myrkr extraction | Destination + separator + entry must fit **32,752 UTF-16 units**, leaving buffer space for temporary suffixes and termination. ZIP names over 4,094 bytes are explicitly rejected. Native readers retain their existing 4,095-byte index-name allowance for compatibility. |
| ZIP format | The name-length field is 16 bits: at most **65,535 bytes**. ZIP64 extends sizes, offsets and counts, not this field. Myrkr's smaller ceiling is an implementation limit, not required for ZIP compatibility. |

ZIP's field definitions are in [PKWARE APPNOTE, sections 4.3.7 and 4.3.12](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).
An archive accepted by the ZIP format is not a guarantee that every extractor
or destination filesystem accepts its paths. Unicode byte counts also differ
from displayed character counts. Choose a shorter extraction destination when
the combined filesystem path is too long; shortening that destination cannot
fix a stored relative name above Myrkr's own limit.

## Native archive correction

The old native writer unnecessarily required a stored name to fit a ustar
header: a split at a separator with at most 155 bytes before it and 100 bytes
after it. This was **not** a 100-byte-per-component rule, and some paths below
256 bytes could not be split that way. Deep Git checkpoint names exposed it.

Native archives already have an authenticated, length-delimited index holding
the complete path. Extraction, browsing, and drag-out use that index. The writer
now retains the old tar header name when it fits; otherwise the unused header
name is the marker `@`, and the **complete, unshortened name stays in the index**.
Directories use a full-size scratch buffer rather than the former 1 KiB buffer.

This deliberately preserves the existing v8 framing and fixed 512-byte header
offset. No PAX or GNU LongLink records are inserted: older index-based readers
would otherwise mistake those records for file contents. Existing v6/v8 files
remain readable. Older index-based versions can read these new names within
their existing limits, but versions before this fix may refuse to re-save them.

The native format is **not a general-purpose tar interchange format**. A tool
that decrypts raw payloads and ignores the authenticated index will see `@` for
these long names; concatenating payloads and feeding them to a tar reader does
not preserve them. Use Myrkr extraction, or ZIP for standard archive interchange.
ZIP output is unchanged by this native-header fallback and carries actual names.

## Rejection behavior

Over-limit source names stop creation or editing with the offending source path
in the error, not just the last successfully added parent directory. Names are
never silently shortened to fit. ZIP reader errors explicitly distinguish
Myrkr's 4,094-byte limit from ZIP's 65,535-byte field limit. Unsafe paths such as
traversal or alternate data streams remain rejected; long-name support is not
permission to bypass name validation.

This correction removes the ustar restriction. It does **not** claim full 32K
relative-name support; lifting the remaining Myrkr limit requires coordinated
changes to browsing, selection, deletion, drag/drop and both archive readers.
