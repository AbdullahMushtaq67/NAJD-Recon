"""Run nmap as a subprocess and stream progress while it works.

Security notes:
  * `asyncio.create_subprocess_exec` takes an argv list and never invokes a shell.
  * The argv comes only from `commands.build_command`.
  * A hard timeout kills nmap if it runs too long, so scans can't pile up.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

ProgressCallback = Callable[[float, str], Awaitable[None]]

# With `--stats-every`, nmap writes elements like this into its XML output:
# <taskprogress task="SYN Stealth Scan" time="1700000000" percent="42.10" remaining="12" .../>
_TASK_PROGRESS = re.compile(rb'<taskprogress task="([^"]+)"[^>]*percent="([\d.]+)"')
_TASK_BEGIN = re.compile(rb'<taskbegin task="([^"]+)"')
_MAX_OUTPUT_BYTES = 20 * 1024 * 1024


class ScanError(RuntimeError):
    """nmap failed, timed out or is missing."""


@dataclass
class RunResult:
    xml: str
    stderr: str
    return_code: int


def nmap_available(nmap_path: str) -> bool:
    return shutil.which(nmap_path) is not None


async def run_nmap(
    argv: list[str],
    *,
    timeout: int,
    on_progress: ProgressCallback | None = None,
) -> RunResult:
    if not nmap_available(argv[0]):
        raise ScanError(f"nmap binary not found: {argv[0]!r}. Is nmap installed?")

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout_pipe, stderr_pipe = proc.stdout, proc.stderr
    if stdout_pipe is None or stderr_pipe is None:  # pragma: no cover - PIPE always set
        raise ScanError("Could not attach to nmap's output")

    async def read_stdout() -> bytes:
        chunks: list[bytes] = []
        size = 0
        while True:
            line = await stdout_pipe.readline()
            if not line:
                break
            size += len(line)
            if size > _MAX_OUTPUT_BYTES:
                raise ScanError("nmap produced more output than allowed")
            chunks.append(line)
            if on_progress:
                if m := _TASK_PROGRESS.search(line):
                    await on_progress(float(m.group(2)), m.group(1).decode(errors="replace"))
                elif m := _TASK_BEGIN.search(line):
                    await on_progress(0.0, m.group(1).decode(errors="replace"))
        return b"".join(chunks)

    async def read_stderr() -> bytes:
        return await stderr_pipe.read()

    try:
        stdout, stderr = await asyncio.wait_for(
            asyncio.gather(read_stdout(), read_stderr()), timeout=timeout
        )
        await proc.wait()
    except TimeoutError as exc:
        _kill(proc)
        raise ScanError(f"Scan timed out after {timeout} seconds") from exc
    except BaseException:
        _kill(proc)  # also covers task cancellation
        raise

    stderr_text = stderr.decode(errors="replace").strip()
    if proc.returncode != 0:
        raise ScanError(_friendly_error(stderr_text) or f"nmap exited with {proc.returncode}")

    return RunResult(
        xml=stdout.decode(errors="replace"), stderr=stderr_text, return_code=proc.returncode
    )


def _kill(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()


def _friendly_error(stderr: str) -> str:
    if "requires root privileges" in stderr or "Operation not permitted" in stderr:
        return (
            "nmap lacks raw-socket privileges for this scan type. Use TCP Connect or "
            "enable NMAP_PRIVILEGED (see README)."
        )
    lines = [ln for ln in stderr.splitlines() if ln.strip()]
    return lines[-1] if lines else ""
