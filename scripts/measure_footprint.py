"""Measure CertFabric's memory under load inside a 512 MB / 1 CPU container.

Starts the image with those limits, adds 250 Devices backed by fake TLS servers on this
machine, waits for the sweep to probe them all, and samples the container's memory.

    uv run python -m scripts.measure_footprint [--engine podman|docker] [--image certfabric:dev]
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import time

import httpx
from cryptography.fernet import Fernet

from tests.fakes.tls_device import FakeTlsDevice

DEVICES = 250
SERVERS = 10
PASSWORD = "footprint-measurement-password"


def _mib(usage: str) -> float:
    value = usage.split("/")[0].strip()
    number = float("".join(c for c in value if c.isdigit() or c == "."))
    unit = value.lstrip("0123456789.").strip().lower()
    return number * {"kb": 1 / 1024, "kib": 1 / 1024, "mb": 1, "mib": 1, "gb": 1024, "gib": 1024, "b": 1 / 1048576}[unit]


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="podman")
    parser.add_argument("--image", default="certfabric:dev")
    parser.add_argument("--port", type=int, default=18090)
    args = parser.parse_args()

    fakes = []
    for _ in range(SERVERS):
        fake = FakeTlsDevice()
        fake.host = "0.0.0.0"  # reachable from the container
        fakes.append(await fake.start())
    container = subprocess.run(
        [args.engine, "run", "-d", "--rm", "--memory", "512m", "--cpus", "1", "-p", f"{args.port}:8080",
         "-e", f"CERTFABRIC_SECRET_KEY={Fernet.generate_key().decode()}", args.image],
        check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip
    samples: list[float] = []

    async def sample() -> None:
        while True:
            out = await asyncio.to_thread(
                subprocess.run,
                [args.engine, "stats", "--no-stream", "--format", "{{.MemUsage}}|{{.CPUPerc}}", container],
                capture_output=True,
                text=True,
            )
            if out.stdout.strip():
                samples.append(_mib(out.stdout.split("|")[0]))
            await asyncio.sleep(0.5)

    sampler = asyncio.create_task(sample())
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{args.port}", timeout=30) as client:
            for _ in range(120):
                try:
                    if (await client.get("/api/auth/status")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
            await client.post("/api/auth/setup", json={"password": PASSWORD})
            idle = samples[-1] if samples else 0.0
            for i in range(DEVICES):
                fake = fakes[i % SERVERS]
                await client.post(
                    "/api/devices",
                    json={"name": f"device-{i:03}", "hostname": "host.containers.internal" if args.engine == "podman"
                          else "host.docker.internal", "port": fake.port, "plugin_id": "generic_ssh_hook"},
                )  # fmt: skip
            started = time.monotonic()
            while True:
                devices = (await client.get("/api/devices")).json()
                probed = sum(1 for d in devices if d["last_scanned_at"])
                if probed == DEVICES or time.monotonic() - started > 180:
                    break
                await asyncio.sleep(1)
            ok = sum(1 for d in devices if d["presented_certificate"])
    finally:
        sampler.cancel()
        subprocess.run([args.engine, "stop", container], capture_output=True)
        for fake in fakes:
            await fake.stop()

    print(f"Devices probed: {probed}/{DEVICES} ({ok} presented a certificate)")
    print(f"Memory: idle {idle:.0f} MiB, peak {max(samples):.0f} MiB of 512 MiB")


if __name__ == "__main__":
    asyncio.run(main())
