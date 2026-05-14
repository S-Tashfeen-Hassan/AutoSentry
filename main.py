from __future__ import annotations

import argparse
import time

from agents.ingest_service import IngestService
from core.graph import AgentGraph
from utils.config import MAX_EVENTS_PER_RUN, TRACE_LOG_PATH

def _truncate_trace_file() -> None:
    TRACE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    TRACE_LOG_PATH.write_text("", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AutoSentry demo-grade NDR pipeline.")
    parser.add_argument("--limit", type=int, default=MAX_EVENTS_PER_RUN, help="Number of recent events to replay")
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Clear the existing trace file before processing the next batch",
    )
    parser.add_argument(
        "--checkpoint",
        action="store_true",
        help="Process the next unread batch from the ingest checkpoint instead of replaying recent events",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Continuously process batches so the dashboard auto-refreshes in realtime",
    )
    parser.add_argument(
        "--mode",
        choices=["replay", "checkpoint"],
        default="replay",
        help="Replay cycles through the local demo file; checkpoint follows unread incoming lines.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Seconds to wait between live batches",
    )
    args = parser.parse_args()

    if args.fresh:
        _truncate_trace_file()

    ingest = IngestService()
    graph = AgentGraph()

    if args.live:
        cursor = 0
        batch_no = 0
        live_mode = args.mode if not args.checkpoint else "checkpoint"
        print(f"AutoSentry live pipeline started in {live_mode} mode. Writing to {TRACE_LOG_PATH}")

        while True:
            if live_mode == "checkpoint":
                logs = ingest.fetch_batch(args.limit)
            else:
                logs, cursor = ingest.replay_slice(cursor, args.limit)

            if logs:
                batch_no += 1
                results = graph.process_many(logs)
                latest = results[-1]
                detection = latest.get("detection_result", {})
                response = latest.get("response_result", {})
                print(
                    f"[batch {batch_no}] processed {len(results)} events | "
                    f"latest={latest.get('event_id')} verdict={detection.get('verdict')} "
                    f"method={detection.get('method')} response={response.get('status')}"
                )
            else:
                print("[idle] no new events available")

            time.sleep(max(0.5, args.interval))
    else:
        logs = ingest.fetch_batch(args.limit) if args.checkpoint else ingest.replay_recent(args.limit)
        results = graph.process_many(logs)

        print(f"AutoSentry processed {len(results)} events into {TRACE_LOG_PATH}")
        if results:
            latest = results[-1]
            detection = latest.get("detection_result", {})
            response = latest.get("response_result", {})
            print(
                "Latest incident:",
                latest.get("event_id"),
                detection.get("verdict"),
                detection.get("method"),
                response.get("status"),
            )

if __name__ == "__main__":
    main()
    raise SystemExit()

