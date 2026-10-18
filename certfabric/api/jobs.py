"""Job status and live output for issuance and Deployments."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, WebSocket, status
from pydantic import BaseModel

from certfabric.jobs import Job

router = APIRouter(tags=["jobs"])


class JobOut(BaseModel):
    id: str
    kind: str
    state: str
    error: str | None
    result: dict[str, Any]
    output: str


def _find(request_or_ws: Request | WebSocket, job_id: str) -> Job | None:
    return request_or_ws.app.state.jobs.get(job_id)


@router.get("/api/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> JobOut:
    job = _find(request, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    return JobOut(id=job.id, kind=job.kind, state=job.state, error=job.error, result=job.result, output=job.output())


@router.websocket("/ws/jobs/{job_id}")
async def follow_job(websocket: WebSocket, job_id: str) -> None:
    """Stream a job's redacted output line by line, then a final message with its outcome."""
    await websocket.accept()
    job = _find(websocket, job_id)
    if job is None:
        await websocket.send_json({"type": "error", "message": "Job not found"})
        await websocket.close()
        return
    async for line in job.follow():
        await websocket.send_json({"type": "line", "text": line})
    await websocket.send_json({"type": "end", "state": job.state, "error": job.error})
    await websocket.close()
