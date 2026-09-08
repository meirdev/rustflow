#!/usr/bin/env python3
"""Watch a directory of rustflow Parquet files and report per-destination-prefix
bit/packet rates over a sliding window, using DuckDB.

Follows the "materialized view" / delta-processor pattern from
https://duckdb.org/2025/10/13/duckdb-streaming-patterns: new Parquet files are
appended to a raw table as soon as they appear, and every reporting interval a
fresh windowed aggregate is MERGEd into a materialized rate table. Old raw rows
are dropped once they fall out of the window.

File arrival is detected with `watchfiles` (inotify / FSEvents) rather than by
polling. rustflow writes each rotated file under a hidden `.tmp` name and
renames it only after the Parquet footer is on disk, so the rename is the
signal that a complete `*.parquet` file exists.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path

import duckdb
from watchfiles import watch

# Prefix lengths the destinations are normalised to.
IPV4_PREFIX = 24
IPV6_PREFIX = 48


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("directory", type=Path, help="rustflow --output directory (Parquet, rotated with --interval)")
    p.add_argument("--every", type=float, default=10, metavar="SECONDS", help="seconds between reports (default 10)")
    p.add_argument("--window", type=int, default=60, metavar="SECONDS", help="sliding window length (default 60)")
    p.add_argument("--top", type=int, default=20, metavar="N", help="rows to print per iteration (default 20)")
    p.add_argument("--db", default="flows.duckdb", help="DuckDB database file (default flows.duckdb, ':memory:' for none)")
    p.add_argument("--once", action="store_true", help="run a single iteration and exit")
    return p.parse_args()


def setup(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("INSTALL inet; LOAD inet;")
    con.execute("SET TimeZone = 'UTC'")
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS loaded_files (
            path      TEXT PRIMARY KEY,
            loaded_at TIMESTAMP NOT NULL
        )
        """
    )
    # Only the columns the aggregate needs; the destination prefix is computed
    # once at load time rather than on every query.
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS flows (
            time_received TIMESTAMP NOT NULL,
            dst_prefix    TEXT      NOT NULL,
            bytes         UBIGINT   NOT NULL,
            packets       UBIGINT   NOT NULL
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS dst_rates (
            dst_prefix   TEXT PRIMARY KEY,
            window_start TIMESTAMP NOT NULL,
            window_end   TIMESTAMP NOT NULL,
            flows        BIGINT    NOT NULL,
            bytes        UBIGINT   NOT NULL,
            packets      UBIGINT   NOT NULL,
            bps          DOUBLE    NOT NULL,
            pps          DOUBLE    NOT NULL
        )
        """
    )


def is_parquet(path: str) -> bool:
    """A finished rustflow output file: `*.parquet` and not a hidden `.tmp`."""
    name = os.path.basename(path)
    return name.endswith(".parquet") and not name.startswith(".")


def scan(directory: Path) -> list[str]:
    return sorted(str(p) for p in directory.rglob("*.parquet") if is_parquet(p.name))


def load_files(con: duckdb.DuckDBPyConnection, candidates: list[str]) -> int:
    """Append rows from the given Parquet files, skipping any loaded before.
    Returns the number of files loaded."""
    if not candidates:
        return 0
    loaded = {row[0] for row in con.execute("SELECT path FROM loaded_files").fetchall()}
    new = [p for p in candidates if p not in loaded and os.path.exists(p)]
    if not new:
        return 0

    con.begin()
    con.execute(
        f"""
        INSERT INTO flows
        SELECT
            time_received_ns::TIMESTAMP AS time_received,
            CASE
                WHEN family(dst_addr::INET) = 4 THEN network((dst_addr || '/{IPV4_PREFIX}')::INET)
                ELSE network((dst_addr || '/{IPV6_PREFIX}')::INET)
            END::VARCHAR AS dst_prefix,
            -- Scale sampled exporters up to the traffic they represent.
            bytes   * coalesce(sampling_rate, 1) AS bytes,
            packets * coalesce(sampling_rate, 1) AS packets
        FROM read_parquet(?)
        WHERE dst_addr IS NOT NULL AND time_received_ns IS NOT NULL
        """,
        [new],
    )
    con.executemany("INSERT INTO loaded_files VALUES (?, now()::TIMESTAMP)", [[p] for p in new])
    con.commit()
    return len(new)


def refresh_rates(con: duckdb.DuckDBPyConnection, window: int) -> tuple[str, str] | None:
    """Recompute the sliding window ending at the newest flow and MERGE it into
    `dst_rates`. Returns (window_start, window_end) or None when there is no data."""
    row = con.execute("SELECT max(time_received) FROM flows").fetchone()
    if row is None or row[0] is None:
        return None

    con.begin()
    con.execute(
        """
        CREATE OR REPLACE TEMP TABLE window_rates AS
        WITH bounds AS (
            SELECT max(time_received) AS window_end,
                   max(time_received) - to_seconds(?) AS window_start
            FROM flows
        )
        SELECT
            dst_prefix,
            bounds.window_start,
            bounds.window_end,
            count(*)      AS flows,
            sum(bytes)    AS bytes,
            sum(packets)  AS packets,
            sum(bytes) * 8.0 / ? AS bps,
            sum(packets) * 1.0 / ? AS pps
        FROM flows, bounds
        WHERE time_received > bounds.window_start AND time_received <= bounds.window_end
        GROUP BY dst_prefix, bounds.window_start, bounds.window_end
        """,
        [window, window, window],
    )
    con.execute(
        """
        MERGE INTO dst_rates AS dest
        USING window_rates AS src
        ON dest.dst_prefix = src.dst_prefix
        WHEN MATCHED THEN UPDATE SET
            window_start = src.window_start, window_end = src.window_end,
            flows = src.flows, bytes = src.bytes, packets = src.packets,
            bps = src.bps, pps = src.pps
        WHEN NOT MATCHED THEN INSERT (dst_prefix, window_start, window_end, flows, bytes, packets, bps, pps)
            VALUES (src.dst_prefix, src.window_start, src.window_end, src.flows, src.bytes, src.packets, src.bps, src.pps)
        """
    )
    # Prefixes with no traffic in the current window drop out of the view.
    con.execute("DELETE FROM dst_rates WHERE window_end <> (SELECT max(window_end) FROM window_rates)")
    # Retention: raw rows older than two windows can never be queried again.
    con.execute("DELETE FROM flows WHERE time_received < (SELECT min(window_start) FROM window_rates) - to_seconds(?)", [window])
    con.commit()

    start, end = con.execute(
        "SELECT strftime(min(window_start), '%H:%M:%S'), strftime(max(window_end), '%H:%M:%S') FROM window_rates"
    ).fetchone()
    return start, end


def human(value: float, unit: str) -> str:
    for prefix in ("", "K", "M", "G", "T"):
        if abs(value) < 1000:
            return f"{value:7.1f} {prefix}{unit}"
        value /= 1000
    return f"{value:7.1f} P{unit}"


def report(con: duckdb.DuckDBPyConnection, top: int, bounds: tuple[str, str] | None, new_files: int) -> None:
    stamp = time.strftime("%H:%M:%S")
    if bounds is None:
        print(f"[{stamp}] no flows yet ({new_files} new files)")
        return
    rows = con.execute(
        "SELECT dst_prefix, flows, bps, pps FROM dst_rates ORDER BY bps DESC, dst_prefix LIMIT ?", [top]
    ).fetchall()
    total = con.execute("SELECT count(*), coalesce(sum(bps), 0), coalesce(sum(pps), 0) FROM dst_rates").fetchone()
    print(f"[{stamp}] window {bounds[0]}..{bounds[1]} UTC | {new_files} new files | "
          f"{total[0]} prefixes | {human(total[1], 'bps').strip()} | {human(total[2], 'pps').strip()}")
    print(f"  {'dst_prefix':<24} {'flows':>7} {'bps':>12} {'pps':>12}")
    for prefix, flows, bps, pps in rows:
        print(f"  {prefix:<24} {flows:>7} {human(bps, 'bps'):>12} {human(pps, 'pps'):>12}")
    print(flush=True)


def main() -> int:
    args = parse_args()
    if not args.directory.is_dir():
        print(f"{args.directory} is not a directory", file=sys.stderr)
        return 2

    # Ctrl-C or SIGTERM (e.g. `docker stop`) sets the event; the watcher
    # returns at its next step and the loop exits after closing the database.
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _signum, _frame: stop.set())

    con = duckdb.connect(args.db)
    setup(con)
    try:
        # Files already on disk are not reported by the watcher.
        new_files = load_files(con, scan(args.directory))
        report(con, args.top, refresh_rates(con, args.window), new_files)
        if args.once:
            return 0

        last_report = time.monotonic()
        # The watcher yields on every batch of file events and, thanks to
        # `yield_on_timeout`, at least once a second, so a report is produced
        # every `--every` seconds whether or not files arrived.
        for changes in watch(
            args.directory,
            watch_filter=lambda _change, path: is_parquet(path),
            rust_timeout=1000,
            yield_on_timeout=True,
            stop_event=stop,
        ):
            new_files += load_files(con, sorted({path for _change, path in changes}))
            if time.monotonic() - last_report >= args.every:
                report(con, args.top, refresh_rates(con, args.window), new_files)
                new_files = 0
                last_report = time.monotonic()
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
