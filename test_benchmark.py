#!/usr/bin/env python3
"""
Performance benchmark: p99 latency at various concurrency levels.

Target: p99 < 150ms at 200 concurrent tenants (2.3 actions/sec sustained).

Run: python3 test_benchmark.py [--concurrency 10] [--duration 30] [--url http://localhost:8000]
"""
import argparse
import asyncio
import time

import httpx


async def run_benchmark(url: str, concurrency: int, duration: int, api_key: str):
    """Run concurrent tool calls for the specified duration and collect latencies."""
    latencies = []
    errors = 0
    stop_time = time.monotonic() + duration
    lock = asyncio.Lock()

    async def worker(worker_id: int):
        nonlocal errors
        async with httpx.AsyncClient(timeout=30) as client:
            while time.monotonic() < stop_time:
                start = time.monotonic()
                try:
                    r = await client.post(f"{url}/mcp/tools/call", json={
                        "agent_id": f"bench-worker-{worker_id}",
                        "agent_type": "benchmark",
                        "agent_version": "1.0.0",
                        "tool": "http",
                        "method": "GET",
                        "params": {"url": "https://httpbin.org/get"},
                    }, headers={"X-API-Key": api_key} if api_key else {})
                    elapsed = (time.monotonic() - start) * 1000  # ms
                    async with lock:
                        latencies.append(elapsed)
                    if r.status_code >= 500:
                        async with lock:
                            errors += 1
                except Exception:
                    async with lock:
                        errors += 1

    print(f"\nStarting benchmark: {concurrency} workers, {duration}s duration...")
    print(f"Target: {url}/mcp/tools/call")
    print()

    workers = [asyncio.create_task(worker(i)) for i in range(concurrency)]
    await asyncio.gather(*workers)

    if not latencies:
        print("No successful requests!")
        return

    latencies.sort()
    total = len(latencies)
    p50 = latencies[int(total * 0.50)]
    p95 = latencies[int(total * 0.95)]
    p99 = latencies[min(int(total * 0.99), total - 1)]
    rps = total / duration
    mean = sum(latencies) / total

    print(f"{'='*60}")
    print(f"Benchmark Results — {concurrency} concurrent workers, {duration}s")
    print(f"{'='*60}")
    print(f"Total requests:  {total}")
    print(f"Errors:          {errors}")
    print(f"Throughput:      {rps:.1f} req/s")
    print(f"Latency mean:    {mean:.1f}ms")
    print(f"Latency p50:     {p50:.1f}ms")
    print(f"Latency p95:     {p95:.1f}ms")
    print(f"Latency p99:     {p99:.1f}ms")
    print(f"Latency max:     {max(latencies):.1f}ms")
    print(f"Latency min:     {min(latencies):.1f}ms")
    print(f"{'='*60}")

    target_p99 = 150
    if p99 < target_p99:
        print(f"\033[92mPASS: p99 ({p99:.1f}ms) < {target_p99}ms target\033[0m")
    else:
        print(f"\033[91mFAIL: p99 ({p99:.1f}ms) >= {target_p99}ms target\033[0m")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vargate performance benchmark")
    parser.add_argument("--url", default="http://localhost:8000", help="Gateway URL")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent workers")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("--api-key", default="", help="API key (optional)")
    args = parser.parse_args()

    asyncio.run(run_benchmark(args.url, args.concurrency, args.duration, args.api_key))
