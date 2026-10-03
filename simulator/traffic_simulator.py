import argparse
import json
import random
import time
from datetime import datetime

import requests

from simulator.generate_dataset import make_flow


NORMAL = [
    "NORMAL_WEB",
    "NORMAL_DNS",
    "NORMAL_SSH",
    "NORMAL_EMAIL",
    "NORMAL_DATABASE",
]

SUSPICIOUS = [
    "HIGH_CONNECTION_RATE",
    "REPEATED_FAILED_CONNECTIONS",
    "MULTI_PORT_PROBING_PATTERN",
    "SYN_HEAVY_PATTERN",
    "UNUSUAL_PORT_ACTIVITY",
    "HIGH_TRAFFIC_VOLUME",
]

API_URL = "http://127.0.0.1:8000/api/flows"


def event(mode):
    if mode == "normal" or (mode == "mixed" and random.random() < 0.75):
        scenario = random.choice(NORMAL)
    else:
        scenario = random.choice(SUSPICIOUS)

    return make_flow(datetime.now(), scenario)


def send_flow(flow):
    try:
        response = requests.post(
            API_URL,
            json=flow,
            timeout=5,
        )

        if response.status_code in (200, 201):
            result = response.json()

            print(
                json.dumps(
                    {
                        "flow_id": flow["flow_id"],
                        "scenario": flow["scenario_type"],
                        "classification": result.get("classification"),
                        "risk_score": result.get("risk_score"),
                        "matched_rules": result.get("matched_rules", []),
                        "alert": result.get("alert"),
                    },
                    default=str,
                ),
                flush=True,
            )

        else:
            print(
                f"[ERROR] API returned {response.status_code}: "
                f"{response.text}",
                flush=True,
            )

    except requests.exceptions.ConnectionError:
        print(
            "[ERROR] Cannot connect to IDS backend at "
            f"{API_URL}. Make sure FastAPI is running.",
            flush=True,
        )

    except requests.exceptions.RequestException as exc:
        print(f"[ERROR] Failed to send flow: {exc}", flush=True)


def stream(mode="mixed", speed="slow"):
    delay = 0.35 if speed == "fast" else 2.0

    print("Network IDS synthetic traffic simulator started.")
    print(f"Mode: {mode}")
    print(f"Speed: {speed}")
    print(f"Backend: {API_URL}")
    print("No real network packets are transmitted.")
    print("Press Ctrl+C to stop.\n")

    while True:
        flow = event(mode)

        # Show the generated flow locally.
        print(
            f"[FLOW] {flow['flow_id']} | "
            f"{flow['scenario_type']} | "
            f"{flow['source_ip']} -> {flow['destination_ip']}",
            flush=True,
        )

        # Send the synthetic flow to the local IDS API.
        send_flow(flow)

        time.sleep(delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Synthetic Network IDS traffic simulator"
    )

    parser.add_argument(
        "--mode",
        choices=["normal", "mixed"],
        default="mixed",
    )

    parser.add_argument(
        "--speed",
        choices=["slow", "fast"],
        default="slow",
    )

    args = parser.parse_args()

    stream(args.mode, args.speed)