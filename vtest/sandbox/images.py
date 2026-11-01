"""Build vtest's sandbox images from the pinned Containerfiles in this package."""

from __future__ import annotations

from dataclasses import dataclass

from vtest.core.runner import (
    K6_IMAGE,
    PYTEST_IMAGE,
    SANDBOX_LABEL,
    ContainerRuntime,
    get_runtime,
    run_tool,
)
from vtest.sandbox import SANDBOX_DIR

IMAGE_SOURCES: dict[str, str] = {
    PYTEST_IMAGE: "pytest.Containerfile",
    K6_IMAGE: "k6.Containerfile",
}


@dataclass
class ImageBuild:
    image: str
    ok: bool
    log: str


async def build_sandbox_images(
    runtime: ContainerRuntime | None = None,
    timeout: int = 900,
) -> list[ImageBuild]:
    """
    Build the pytest and k6 sandbox images. Base images are pinned by digest
    in the Containerfiles and pulled only if missing. With Podman, build steps
    run with all capabilities dropped.
    """
    rt = runtime or await get_runtime()
    results: list[ImageBuild] = []
    for image, containerfile in IMAGE_SOURCES.items():
        argv = [rt.path, "build", "--pull=missing", "--tag", image,
                "--label", SANDBOX_LABEL, "--file", str(SANDBOX_DIR / containerfile)]
        if rt.kind == "podman":
            argv += ["--cap-drop=ALL", "--security-opt=no-new-privileges"]
        argv.append(str(SANDBOX_DIR))
        res = await run_tool(argv, cwd=SANDBOX_DIR, timeout=timeout)
        results.append(ImageBuild(image=image, ok=res.returncode == 0, log=res.output))
    return results
