"""External images must be pinned by digest so a re-tagged image cannot change a build."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def _from_images(dockerfile: Path) -> list[str]:
    images, stages = [], set()
    for line in dockerfile.read_text().splitlines():
        tokens = line.split()
        if not tokens or tokens[0].upper() != "FROM":
            continue
        refs = [t for t in tokens[1:] if not t.startswith("--")]
        image = refs[0]
        if image not in stages:  # FROM <earlier stage> is not an external image
            images.append(image)
        if len(refs) >= 3 and refs[1].upper() == "AS":
            stages.add(refs[2])
    return images


def test_dockerfile_images_are_pinned_by_digest():
    images = _from_images(ROOT / "docker" / "Dockerfile")
    assert len(images) >= 5
    unpinned = [i for i in images if not DIGEST.search(i)]
    assert not unpinned, f"pin by digest: {unpinned}"


def test_e2e_images_are_pinned_by_digest():
    compose = yaml.safe_load((ROOT / "tests" / "e2e" / "compose.yaml").read_text())
    images = [s["image"] for s in compose["services"].values() if "build" not in s]
    assert images
    unpinned = [i for i in images if not DIGEST.search(i)]
    assert not unpinned, f"pin by digest: {unpinned}"
