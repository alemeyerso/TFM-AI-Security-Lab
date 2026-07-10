import json
import subprocess
import time

BASE_URL = "http://localhost:8000"
MODEL = "qwen3.5:2b"

VECTORS = [
    "direct",
    "indirect",
    "jailbreak",
    "tool_abuse",
]


def get_payloads(vector):
    result = subprocess.run(
        ["curl", "-s", f"{BASE_URL}/api/payloads/{vector}"],
        capture_output=True,
        text=True,
        check=True,
    )

    data = json.loads(result.stdout)
    return data.get("payloads", [])


def run_attack(vector, payload_id):
    payload = {
        "vector": vector,
        "model": MODEL,
        "payload_id": payload_id,
    }

    result = subprocess.run(
        [
            "curl",
            "-s",
            "-X",
            "POST",
            f"{BASE_URL}/api/attack",
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps(payload),
        ],
        capture_output=True,
        text=True,
    )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "error": "Invalid JSON response",
            "raw_response": result.stdout,
            "stderr": result.stderr,
        }


def main():
    total = 0

    print("=" * 60)
    print("TFM AI SECURITY LAB")
    print("Baseline experiment")
    print(f"Model: {MODEL}")
    print("=" * 60)

    for vector in VECTORS:
        payloads = get_payloads(vector)

        print()
        print(f"===== {vector.upper()} =====")
        print(f"Payloads found: {len(payloads)}")

        for index, payload in enumerate(payloads, start=1):
            payload_id = payload["id"]

            print(
                f"[{index}/{len(payloads)}] "
                f"{vector} / {payload_id}",
                flush=True,
            )

            start = time.time()

            response = run_attack(vector, payload_id)

            elapsed = time.time() - start

            outcome = response.get("outcome", "ERROR")
            latency = response.get("latency_ms", "N/A")

            print(
                f"    outcome={outcome} "
                f"latency={latency} ms "
                f"wall_time={elapsed:.1f}s",
                flush=True,
            )

            if "error" in response:
                print(
                    f"    ERROR: {response.get('raw_response', '')}",
                    flush=True,
                )

            total += 1

    print()
    print("=" * 60)
    print(f"TOTAL TESTS EXECUTED: {total}")
    print("=" * 60)


if __name__ == "__main__":
    main()
