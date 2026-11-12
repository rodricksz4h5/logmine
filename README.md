# logmine

Exact, local intelligence over large log files, as three Hermes tools. A language
model can't read a 500 MB log, and asked to "find the top errors" it will guess.
logmine streams the file on disk and returns **ground truth**: the recurring
message patterns with exact counts, a level histogram, the time span, regex search
with context, and an event-over-time histogram.

## Why a tool and not a prompt or skill

The core is **message-template mining**. Real logs are the same handful of messages
repeated with different variable parts:

```
2026-11-11T09:14:02 ERROR user 48213 auth failed from 10.2.3.4
2026-11-11T09:14:03 ERROR user 90017 auth failed from 10.2.9.7
2026-11-11T09:14:05 ERROR user 11882 auth failed from 10.8.1.2
```

logmine masks the variable parts (`<NUM>`, `<IP>`, `<UUID>`, `<HEX>`, `<STR>`,
`<TS>`) and collapses those into **one** pattern with a count:

```
ERROR user <NUM> auth failed from <IP>    ×3
```

That turns a noisy multi-gigabyte log into a short ranked list of *what actually
happened* — computation over data that never fits in a prompt, and something a
skill (which just instructs the model) cannot do reliably either.

## Tools

### `log_summarize`
Mine the file into ranked templates + a level histogram + the detected time span.

| arg | type | required | default | meaning |
|---|---|---|---|---|
| `path` | string | yes | — | local log file |
| `max_patterns` | integer | no | `20` | top-N templates (cap 200) |
| `level` | string | no | — | only consider this level (e.g. `ERROR`) |

Returns: `{ ok, total_lines, level_histogram, time_span:{first,last}, distinct_patterns, top_patterns:[{template,count,example,first_line,last_line}] }`.

### `log_grep`
Regex search with line numbers and optional context lines.

| arg | type | required | default | meaning |
|---|---|---|---|---|
| `path` | string | yes | — | local log file |
| `pattern` | string | yes | — | Python `re` pattern |
| `context` | integer | no | `0` | context lines before/after each match (cap 50) |
| `ignore_case` | boolean | no | `false` | case-insensitive |
| `max_matches` | integer | no | `100` | max matches returned (cap 1000) |

Returns matches with `before`/`after` context arrays when `context > 0`.

### `log_timeline`
Count events per time bucket from detected timestamps.

| arg | type | required | default | meaning |
|---|---|---|---|---|
| `path` | string | yes | — | local log file |
| `bucket` | string | no | `hour` | `minute` \| `hour` \| `day` |
| `level` | string | no | — | only count this level |

Returns an ordered `series:[{bucket,count}]` and the `peak` bucket.

All three always return a JSON string; a bad path or invalid regex returns
`{ "ok": false, "error": "..." }` rather than raising.

## What it understands

- **Timestamps:** ISO 8601 (`2026-11-11T13:04:11`, space variant, optional
  fractional seconds), slash dates (`2026/11/11 13:04:11`), Apache/nginx
  common-log (`11/Nov/2026:13:04:11`), and syslog (`Nov 11 13:04:11`).
- **Levels:** `CRITICAL FATAL ERROR WARN NOTICE INFO DEBUG TRACE` (with `ERR`→`ERROR`,
  `WARNING`→`WARN`).
- **Masked tokens in templates:** timestamps, UUIDs, IPv4(:port), `0x`/hash hex,
  quoted strings, and numbers.

## Safety and disclosure

- **Reads only the file path you pass**, read-only. Never writes, deletes, or
  touches any other path.
- **Honours Hermes' read denylist.** When running inside the agent, every path
  is passed through the same check Core's `read_file` uses, so credential
  stores, internal caches and `.env` files are refused — logmine can't be used
  to read what the host protects.
- **Regular files only.** Like Core's `read_file`, paths under `/proc` and `/dev`
  (including symlinks that resolve there) are refused, and so is anything that
  isn't a regular file — FIFOs, sockets and devices — before the file is opened.
- **No network, no credentials, no telemetry, no background processes, no
  self-update.** Standard library only.
- A single call stops after 5,000,000 lines, truncates lines over 100,000 chars
  (reading them in bounded pieces, so a huge file with no newlines is never held
  in memory whole), and caps distinct templates at 50,000 — all flagged in the
  result — so runtime and memory stay bounded. A pathological regex you pass to `log_grep` on a huge
  file can still be slow; that is the only sharp edge.

## Install

```bash
hermes plugins install rodricksz4h5/logmine
```

## License

MIT — see [LICENSE](./LICENSE).
