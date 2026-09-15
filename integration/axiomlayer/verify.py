#!/usr/bin/env python3
"""Fail-closed verifier for AxiomLayer's pinned ripgrep integration lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
DEFAULT_MANIFEST = HERE / "ripgrep-15.2.0.json"
INTEGRATION_WORKFLOW = Path(".github/workflows/axiomlayer-integration.yml")
FORK_REPOSITORY = "axiomlayer/ripgrep"
FORK_DEFAULT_BRANCH = "master"
FORK_DEFAULT_REF = "refs/heads/master"
INTEGRATION_WORKFLOW_REF = (
    "axiomlayer/ripgrep/.github/workflows/axiomlayer-integration.yml@refs/heads/master"
)
UPSTREAM_WORKFLOW_BASELINE = "3fce3b5bb0236da2df6d99672afb8a719642eca7"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")
REMOTE_USE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(['\"]?)([^'\"\s#]+)\1\s*(?:#.*)?$")
USE_KEY = re.compile(r"^\s*(?:-\s*)?uses\s*:")
EXPECTED_TARGETS = {
    "darwin-aarch64",
    "darwin-x86_64",
    "linux-aarch64",
    "linux-x86_64",
    "windows-aarch64",
    "windows-x86_64",
}
EXPECTED_TARGET_METADATA = {
    "darwin-aarch64": {
        "runner": "macos-15",
        "nixSystem": "aarch64-darwin",
        "buildMode": "nix-native",
        "archiveName": "ripgrep-15.2.0-aarch64-apple-darwin.tar.gz",
        "archiveRoot": "ripgrep-15.2.0-aarch64-apple-darwin",
        "binary": "rg",
        "promotionName": "ripgrep-aarch64-apple-darwin.tar.gz",
    },
    "darwin-x86_64": {
        "runner": "macos-15-intel",
        "nixSystem": "x86_64-darwin",
        "buildMode": "nix-native",
        "archiveName": "ripgrep-15.2.0-x86_64-apple-darwin.tar.gz",
        "archiveRoot": "ripgrep-15.2.0-x86_64-apple-darwin",
        "binary": "rg",
        "promotionName": "ripgrep-x86_64-apple-darwin.tar.gz",
    },
    "linux-aarch64": {
        "runner": "ubuntu-24.04-arm",
        "nixSystem": "aarch64-linux",
        "buildMode": "nix-native",
        "archiveName": "ripgrep-15.2.0-aarch64-unknown-linux-gnu.tar.gz",
        "archiveRoot": "ripgrep-15.2.0-aarch64-unknown-linux-gnu",
        "binary": "rg",
        "promotionName": "ripgrep-aarch64-linux-gnu.tar.gz",
    },
    "linux-x86_64": {
        "runner": "ubuntu-24.04",
        "nixSystem": "x86_64-linux",
        "buildMode": "nix-native",
        "archiveName": "ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz",
        "archiveRoot": "ripgrep-15.2.0-x86_64-unknown-linux-musl",
        "binary": "rg",
        "promotionName": "ripgrep-x86_64-linux-musl.tar.gz",
    },
    "windows-aarch64": {
        "runner": "windows-11-arm",
        "nixSystem": None,
        "buildMode": "cargo-native",
        "archiveName": "ripgrep-15.2.0-aarch64-pc-windows-msvc.zip",
        "archiveRoot": "ripgrep-15.2.0-aarch64-pc-windows-msvc",
        "binary": "rg.exe",
        "promotionName": "ripgrep-aarch64-windows-msvc.zip",
    },
    "windows-x86_64": {
        "runner": "windows-2025",
        "nixSystem": None,
        "buildMode": "cargo-native",
        "archiveName": "ripgrep-15.2.0-x86_64-pc-windows-msvc.zip",
        "archiveRoot": "ripgrep-15.2.0-x86_64-pc-windows-msvc",
        "binary": "rg.exe",
        "promotionName": "ripgrep-x86_64-windows-msvc.zip",
    },
}
TARGET_FIELDS = {
    "runner",
    "nixSystem",
    "buildMode",
    "archiveName",
    "archiveBytes",
    "archiveUrl",
    "promotionUrl",
    "archiveSha256",
    "archiveRoot",
    "binary",
    "binarySha256",
}
EXPECTED_NIX_SYSTEMS = {
    "aarch64-darwin",
    "aarch64-linux",
    "x86_64-darwin",
    "x86_64-linux",
}
EXPECTED_JOB_RUNNERS = (
    "ubuntu-24.04",
    "${{ matrix.runner }}",
    "ubuntu-24.04",
)
EXPECTED_MATRIX_RUNNERS = (
    "macos-15",
    "macos-15-intel",
    "ubuntu-24.04-arm",
    "ubuntu-24.04",
    "windows-11-arm",
    "windows-2025",
)
EXPECTED_TRIGGER_BLOCK = """on:
  pull_request:
    branches:
      - master
  push:
    branches:
      - master
  schedule:
    - cron: '17 6 * * *'
  workflow_dispatch:"""
TRUSTED_WORKFLOW_CONDITION = (
    "github.repository == 'axiomlayer/ripgrep' && "
    "github.event.repository.default_branch == 'master' && "
    "((github.event_name == 'pull_request' && "
    "github.event.pull_request.base.repo.full_name == 'axiomlayer/ripgrep' && "
    "github.event.pull_request.head.repo.full_name == 'axiomlayer/ripgrep' && "
    "github.base_ref == 'master' && "
    "github.ref == format('refs/pull/{0}/merge', github.event.number) && "
    "github.workflow_ref == format('axiomlayer/ripgrep/.github/workflows/"
    "axiomlayer-integration.yml@refs/pull/{0}/merge', github.event.number)) || "
    "(github.event_name == 'push' && "
    "github.ref == 'refs/heads/master' && "
    "github.ref_protected == true && "
    f"github.workflow_ref == '{INTEGRATION_WORKFLOW_REF}') || "
    "(github.event_name == 'schedule' && "
    "github.ref == 'refs/heads/master' && "
    "github.ref_protected == true && "
    f"github.workflow_ref == '{INTEGRATION_WORKFLOW_REF}') || "
    "(github.event_name == 'workflow_dispatch' && "
    "github.ref == 'refs/heads/master' && "
    "github.ref_protected == true && "
    f"github.workflow_ref == '{INTEGRATION_WORKFLOW_REF}'))"
)


class VerificationError(RuntimeError):
    pass


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def run_git(*args: str, root: Path = REPOSITORY_ROOT) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise VerificationError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout.strip()


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError("manifest root must be an object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def workflow_context_allowed(
    repository: str,
    default_branch: str,
    event_name: str,
    ref: str,
    *,
    base_ref: str = "",
    base_repository: str = "",
    head_repository: str = "",
    workflow_ref: str = "",
    ref_protected: bool = False,
    event_number: int | None = None,
) -> bool:
    """Model the exact contexts admitted by the workflow's job firewall."""

    if repository != FORK_REPOSITORY or default_branch != FORK_DEFAULT_BRANCH:
        return False
    if event_name == "pull_request":
        return (
            base_repository == FORK_REPOSITORY
            and head_repository == FORK_REPOSITORY
            and base_ref == FORK_DEFAULT_BRANCH
            and type(event_number) is int
            and event_number > 0
            and ref == f"refs/pull/{event_number}/merge"
            and workflow_ref
            == (
                "axiomlayer/ripgrep/.github/workflows/axiomlayer-integration.yml"
                f"@refs/pull/{event_number}/merge"
            )
        )
    if event_name == "push":
        return (
            ref == FORK_DEFAULT_REF
            and ref_protected is True
            and workflow_ref == INTEGRATION_WORKFLOW_REF
        )
    if event_name in {"schedule", "workflow_dispatch"}:
        return (
            ref == FORK_DEFAULT_REF
            and ref_protected is True
            and workflow_ref == INTEGRATION_WORKFLOW_REF
        )
    return False


def require_safe_repository_path(value: Any, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a path")
    require("\\" not in value, f"{label} must use POSIX separators")
    path = PurePosixPath(value)
    require(not path.is_absolute(), f"{label} must be repository-relative")
    require(".." not in path.parts, f"{label} escapes the repository")
    require(path.as_posix() == value, f"{label} is not normalized")
    return value


def validate_workflow_firewall_manifest(manifest: dict[str, Any]) -> None:
    firewall = manifest.get("workflowFirewall")
    require(isinstance(firewall, dict), "workflowFirewall must be an object")
    require(
        set(firewall) == {"activeWorkflow", "upstreamArchive"},
        "workflowFirewall fields drifted",
    )
    active = firewall.get("activeWorkflow")
    require(isinstance(active, dict), "active workflow record is missing")
    require(
        set(active) == {"path", "sha256"},
        "active workflow record fields drifted",
    )
    active_path = require_safe_repository_path(
        active.get("path"), "active workflow path"
    )
    require(
        active_path == INTEGRATION_WORKFLOW.as_posix(),
        "unexpected active workflow path",
    )
    require(
        HEX_SHA256.fullmatch(str(active.get("sha256", ""))) is not None,
        "active workflow digest must be SHA-256",
    )

    archive = firewall.get("upstreamArchive")
    require(isinstance(archive, dict), "upstream workflow archive is missing")
    require(
        set(archive) == {"repository", "commit", "sourceRoots", "archiveRoot", "files"},
        "upstream workflow archive fields drifted",
    )
    require(
        archive.get("repository") == "BurntSushi/ripgrep",
        "unexpected upstream workflow repository",
    )
    require(
        archive.get("commit") == UPSTREAM_WORKFLOW_BASELINE,
        "unexpected upstream workflow baseline commit",
    )
    require(
        archive.get("commit") == manifest["promotion"]["upstreamBaselineCommit"],
        "workflow and source baselines disagree",
    )
    source_roots_value = archive.get("sourceRoots")
    require(
        isinstance(source_roots_value, list) and source_roots_value,
        "upstream workflow source roots are missing",
    )
    source_roots = [
        require_safe_repository_path(value, "upstream workflow source root")
        for value in source_roots_value
    ]
    archive_root = require_safe_repository_path(
        archive.get("archiveRoot"), "upstream workflow archive root"
    )
    require(
        source_roots == [".github/workflows", "ci"],
        "unexpected workflow or support source roots",
    )
    require(
        archive_root == "integration/axiomlayer/upstream-workflows",
        "unexpected workflow archive root",
    )

    entries = archive.get("files")
    require(isinstance(entries, list) and entries, "workflow archive files are missing")
    source_paths: list[str] = []
    archive_paths: list[str] = []
    for index, entry in enumerate(entries):
        label = f"workflowFirewall.upstreamArchive.files[{index}]"
        require(isinstance(entry, dict), f"{label} must be an object")
        require(
            set(entry) == {"sourcePath", "archivePath", "gitMode", "sha256"},
            f"{label} fields drifted",
        )
        source_path = require_safe_repository_path(
            entry.get("sourcePath"), f"{label}.sourcePath"
        )
        archive_path = require_safe_repository_path(
            entry.get("archivePath"), f"{label}.archivePath"
        )
        matching_roots = [
            source_root
            for source_root in source_roots
            if source_path.startswith(f"{source_root}/")
        ]
        require(
            len(matching_roots) == 1,
            f"{label}.sourcePath is outside the source roots",
        )
        require(
            archive_path == f"{archive_root}/{source_path}",
            f"{label}.archivePath does not preserve the full upstream path",
        )
        require(
            entry.get("gitMode") in {"100644", "100755"},
            f"{label}.gitMode is invalid",
        )
        require(
            HEX_SHA256.fullmatch(str(entry.get("sha256", ""))) is not None,
            f"{label}.sha256 must be SHA-256",
        )
        source_paths.append(source_path)
        archive_paths.append(archive_path)
    require(
        source_paths == sorted(set(source_paths)),
        "workflow archive source paths must be sorted and unique",
    )
    require(
        archive_paths == sorted(set(archive_paths)),
        "workflow archive paths must be sorted and unique",
    )


def validate_manifest(manifest: dict[str, Any]) -> None:
    require(
        set(manifest)
        == {
            "schema",
            "revision",
            "promotion",
            "workflowActions",
            "workflowFirewall",
            "nix",
            "credentials",
            "targets",
            "unsupportedHostedProof",
        },
        "manifest fields drifted",
    )
    require(
        manifest.get("schema") == "axiomlayer-ripgrep-integration-v1",
        "unexpected manifest schema",
    )
    require(manifest.get("revision") == 2, "unexpected manifest revision")
    promotion = manifest.get("promotion")
    require(isinstance(promotion, dict), "promotion must be an object")
    require(
        set(promotion)
        == {
            "candidateId",
            "authority",
            "authorityCommit",
            "authorityRuntimeManifestSha256",
            "forkRepository",
            "upstreamRepository",
            "upstreamBaselineCommit",
            "commit",
            "tag",
            "version",
            "rustToolchain",
            "deliveryOrigin",
        },
        "promotion fields drifted",
    )
    require(
        promotion.get("forkRepository") == "axiomlayer/ripgrep",
        "fork repository must be axiomlayer/ripgrep",
    )
    require(
        promotion.get("upstreamRepository") == "BurntSushi/ripgrep",
        "upstream repository must be BurntSushi/ripgrep",
    )
    require(promotion.get("version") == "15.2.0", "version must be 15.2.0")
    require(promotion.get("tag") == "15.2.0", "tag must be 15.2.0")
    require(
        HEX_COMMIT.fullmatch(str(promotion.get("authorityCommit", ""))) is not None,
        "Dotfiles authority commit must be full",
    )
    require(
        HEX_SHA256.fullmatch(str(promotion.get("authorityRuntimeManifestSha256", "")))
        is not None,
        "Dotfiles runtime manifest digest must be SHA-256",
    )
    require(
        HEX_COMMIT.fullmatch(str(promotion.get("commit", ""))) is not None,
        "promotion commit must be a full Git commit",
    )
    require(
        HEX_COMMIT.fullmatch(str(promotion.get("upstreamBaselineCommit", "")))
        is not None,
        "upstream baseline must be a full Git commit",
    )
    delivery_origin = promotion.get("deliveryOrigin")
    require(
        delivery_origin == "https://install.axiomlayer.com/runtime/ripgrep/15.2.0",
        "delivery origin diverges from Dotfiles #49",
    )

    require(
        manifest.get("workflowActions")
        == {
            "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
            "dtolnay/rust-toolchain": "02cb101ec7c40f2c49e1d9714d64511d8e1b74de",
        },
        "workflow Action allowlist changed without review",
    )
    validate_workflow_firewall_manifest(manifest)

    credentials = manifest.get("credentials")
    require(isinstance(credentials, dict), "credentials must be an object")
    require(
        set(credentials) == {"required", "fabricated", "statement"},
        "credential declaration fields drifted",
    )
    require(credentials.get("required") == [], "real credentials are forbidden")
    require(credentials.get("fabricated") == [], "fake credentials are forbidden")

    targets = manifest.get("targets")
    require(isinstance(targets, dict), "targets must be an object")
    require(set(targets) == EXPECTED_TARGETS, "native target coverage is incomplete")
    seen_runners: set[str] = set()
    for target, spec in targets.items():
        require(isinstance(spec, dict), f"{target}: target must be an object")
        require(set(spec) == TARGET_FIELDS, f"{target}: target fields drifted")
        expected_metadata = EXPECTED_TARGET_METADATA[target]
        for field in (
            "runner",
            "nixSystem",
            "buildMode",
            "archiveName",
            "archiveRoot",
            "binary",
        ):
            require(
                spec.get(field) == expected_metadata[field],
                f"{target}: {field} drifted",
            )
        runner = spec.get("runner")
        require(isinstance(runner, str) and runner, f"{target}: runner is missing")
        require(runner not in seen_runners, f"{target}: runner label is duplicated")
        seen_runners.add(runner)
        for field in ("archiveSha256", "binarySha256"):
            require(
                HEX_SHA256.fullmatch(str(spec.get(field, ""))) is not None,
                f"{target}: {field} must be a SHA-256 digest",
            )
        require(
            type(spec.get("archiveBytes")) is int and spec["archiveBytes"] > 0,
            f"{target}: archiveBytes must be positive",
        )
        require(
            spec.get("archiveUrl")
            == "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/"
            + str(spec.get("archiveName")),
            f"{target}: upstream release URL is not canonical",
        )
        require(
            spec.get("promotionUrl")
            == f"{delivery_origin}/{expected_metadata['promotionName']}",
            f"{target}: promotion URL drifted",
        )
        if target.startswith("windows-"):
            require(spec.get("buildMode") == "cargo-native", f"{target}: bad mode")
            require(spec.get("nixSystem") is None, f"{target}: Nix must be unsupported")
            require(spec.get("binary") == "rg.exe", f"{target}: bad binary name")
        else:
            require(spec.get("buildMode") == "nix-native", f"{target}: bad mode")
            require(
                spec.get("nixSystem") in EXPECTED_NIX_SYSTEMS,
                f"{target}: missing Nix system",
            )
            require(spec.get("binary") == "rg", f"{target}: bad binary name")

    nix = manifest.get("nix")
    require(isinstance(nix, dict), "nix must be an object")
    require(
        set(nix)
        == {
            "version",
            "installerUrl",
            "installerSha256",
            "wrapperSha256",
            "expressionSha256",
            "binaryTarballSha256",
            "nixpkgs",
            "systems",
        },
        "Nix declaration fields drifted",
    )
    require(
        nix.get("systems")
        == ["aarch64-darwin", "aarch64-linux", "x86_64-darwin", "x86_64-linux"],
        "bad Nix systems",
    )
    require(nix.get("version") == "2.35.2", "Nix version diverges from Dotfiles #49")
    require(
        nix.get("installerUrl") == "https://releases.nixos.org/nix/nix-2.35.2/install",
        "Nix installer URL diverges from Dotfiles #49",
    )
    require(
        nix.get("installerSha256")
        == "9adda97297d9e8ab360df95c729eabff4f4f93d6db091953c3a68f29e3fb130c",
        "Nix installer digest changed without review",
    )
    require(
        nix.get("wrapperSha256")
        == "4b8c7ba5d229ad75d19ffed8b7b3330185ebd049f3aa2a27e106d187ad7ef2aa",
        "Nix bootstrap wrapper digest changed without review",
    )
    require(
        nix.get("expressionSha256")
        == "557c2cbbee6e5fa25eff7923b3c13057d39a1c334fb5894f4901e877f944eda3",
        "Nix expression digest changed without review",
    )
    require(
        nix.get("binaryTarballSha256")
        == {
            "aarch64-darwin": "1695c13aba5afa7c2ecd6dc4a9393f602e7bbc440ed45e81602c831546580ec3",
            "x86_64-darwin": "d725518d89f3b0b8d4af702a9d38d519814014cbe125afb3ed0545c9d755f6a5",
            "aarch64-linux": "4d0302a2910f5eec1c33b8deef634f04899a75737e7001ec49908d003ae5efda",
            "x86_64-linux": "0c3960a9792331a22081c3c7a5d8465db9b17c50b3acdf18587fa4c6f2cb1158",
        },
        "Nix platform digest table changed without review",
    )
    nixpkgs = nix.get("nixpkgs")
    require(isinstance(nixpkgs, dict), "nixpkgs must be an object")
    require(
        nixpkgs
        == {
            "repository": "NixOS/nixpkgs",
            "role": "build-only input pending its own AxiomLayer integration lane",
            "commit": "c3eea5b2156db11c7eeeada3dc737711255b253e",
            "url": (
                "https://github.com/NixOS/nixpkgs/archive/"
                "c3eea5b2156db11c7eeeada3dc737711255b253e.tar.gz"
            ),
            "narHash": "sha256-vdhpDJ3Lr24lkZ+fDCjmBRRtw9/vcSzkqGJOJyF5h2U=",
        },
        "Nixpkgs identity drifted",
    )

    unsupported = manifest.get("unsupportedHostedProof")
    require(isinstance(unsupported, list), "unsupported proof must be a list")
    unsupported_targets = {
        target
        for proof in unsupported
        if isinstance(proof, dict)
        for target in proof.get("targets", [])
    }
    require(
        {"windows-aarch64", "windows-x86_64", "wsl-aarch64", "wsl-x86_64"}
        <= unsupported_targets,
        "unsupported Windows-Nix and WSL proof must be explicit",
    )


def verify_source(manifest: dict[str, Any], root: Path = REPOSITORY_ROOT) -> None:
    validate_manifest(manifest)
    promotion = manifest["promotion"]
    commit = promotion["commit"]
    baseline = promotion["upstreamBaselineCommit"]
    tag_commit = run_git("rev-parse", f"{promotion['tag']}^{{commit}}", root=root)
    require(tag_commit == commit, f"tag resolves to {tag_commit}, not {commit}")
    run_git("cat-file", "-e", f"{commit}^{{commit}}", root=root)
    run_git("cat-file", "-e", f"{baseline}^{{commit}}", root=root)
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, baseline],
        cwd=root,
        check=False,
    )
    require(ancestry.returncode == 0, "promoted commit is not in the fork baseline")
    cargo_toml = run_git("show", f"{commit}:Cargo.toml", root=root)
    package = cargo_toml.split("[workspace]", 1)[0]
    version = re.search(r'^version\s*=\s*"([^"]+)"', package, re.MULTILINE)
    require(version is not None, "Cargo package version is missing")
    require(
        version.group(1) == promotion["version"], "Cargo version does not match pin"
    )


def workflow_job_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines(keepends=True)
    in_jobs = False
    current: str | None = None
    blocks: dict[str, list[str]] = {}
    for line in lines:
        if line == "jobs:\n" or line == "jobs:\r\n":
            in_jobs = True
            continue
        if in_jobs and line and not line[0].isspace():
            break
        job_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if in_jobs and job_match:
            current = job_match.group(1)
            blocks[current] = [line]
        elif in_jobs and current is not None:
            blocks[current].append(line)
    return {name: "".join(lines_) for name, lines_ in blocks.items()}


def compact_expression(value: str) -> str:
    compact: list[str] = []
    quote: str | None = None
    escaped = False
    for character in value:
        if quote is not None:
            compact.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            compact.append(character)
        elif not character.isspace():
            compact.append(character)
    require(quote is None, "workflow job condition contains an unterminated quote")
    return "".join(compact)


def workflow_job_condition(block: str) -> str | None:
    lines = block.splitlines()
    entries = [
        (index, match.group(1).strip())
        for index, line in enumerate(lines)
        if (match := re.fullmatch(r"    if:\s*(.*?)\s*", line))
    ]
    require(len(entries) <= 1, "workflow job contains duplicate if keys")
    if not entries:
        return None
    index, value = entries[0]
    if value not in {">", ">-", "|", "|-"}:
        return value or None
    continuation: list[str] = []
    for line in lines[index + 1 :]:
        indentation = len(line) - len(line.lstrip(" "))
        if line.strip() and indentation <= 4:
            break
        if line.strip():
            continuation.append(line.strip())
    return " ".join(continuation) or None


def checkout_step_blocks(text: str) -> list[tuple[int, str]]:
    lines = text.splitlines()
    blocks: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = REMOTE_USE.fullmatch(line)
        if match is None or not match.group(2).startswith("actions/checkout@"):
            continue
        use_indentation = len(line) - len(line.lstrip(" "))
        block = [line]
        for following in lines[index + 1 :]:
            stripped = following.lstrip(" ")
            indentation = len(following) - len(stripped)
            if stripped.startswith("- ") and indentation < use_indentation:
                break
            if stripped and indentation < max(0, use_indentation - 2):
                break
            block.append(following)
        blocks.append((use_indentation, "\n".join(block)))
    return blocks


def discover_axiomlayer_workflow(workflow_paths: list[Path]) -> Path:
    candidates: list[Path] = []
    for path in workflow_paths:
        text = path.read_text(encoding="utf-8")
        name = re.search(r"(?m)^name:\s*([^#]+?)\s*$", text)
        if "axiomlayer" in path.name.lower() or (
            name is not None and "axiomlayer" in name.group(1).lower()
        ):
            candidates.append(path)
    require(
        len(candidates) == 1,
        "expected exactly one active AxiomLayer workflow",
    )
    require(
        candidates[0].as_posix().endswith(INTEGRATION_WORKFLOW.as_posix()),
        "unexpected active AxiomLayer workflow path",
    )
    return candidates[0]


def verify_action_references(
    text: str, path: Path, expected_actions: dict[str, str]
) -> set[str]:
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        match = REMOTE_USE.fullmatch(line)
        if not match:
            require(
                USE_KEY.search(line) is None,
                f"{path}:{line_number}: action reference is not statically parseable",
            )
            continue
        use = match.group(2)
        if use.startswith("./") or use.startswith("docker://"):
            continue
        require("@" in use, f"{path}:{line_number}: action ref is missing")
        action, reference = use.rsplit("@", 1)
        require(
            HEX_COMMIT.fullmatch(reference) is not None,
            f"{path}:{line_number}: {use} is not pinned to a full commit",
        )
        require(
            action in expected_actions,
            f"{path}:{line_number}: unreviewed workflow Action {action}",
        )
        require(
            reference == expected_actions[action],
            f"{path}:{line_number}: {action} uses an unexpected commit",
        )
        seen.add(action)
    return seen


def verify_integration_boundaries(text: str) -> None:
    forbidden = {
        "secret reference": (
            r"(?<![-A-Za-z0-9_])secrets\s*(?:\.|\[)|"
            r"(?<![-A-Za-z0-9_])github\s*(?:\.\s*token|"
            r"\[\s*['\"]token['\"]\s*\])"
        ),
        "repository variable reference": (r"(?<![-A-Za-z0-9_])vars\s*(?:\.|\[)"),
        "explicit credential surface": (
            r"^[ \t]+(?:token|github-token)[ \t]*:|"
            r"\b(?:GITHUB_TOKEN|GH_TOKEN|ACTIONS_RUNTIME_TOKEN|"
            r"CARGO_REGISTRY_TOKEN|NPM_TOKEN)\b|"
            r"\b(?:authorization|http\.extraheader|credential\.helper)\b"
        ),
        "write authority": (r"^[ \t]+[A-Za-z-]+[ \t]*:[ \t]*write[ \t]*(?:#.*)?$"),
        "deployment environment": r"^[ \t]*environment[ \t]*:",
        "privileged or chained event": (
            r"^[ \t]*(?:pull_request_target|repository_dispatch|"
            r"workflow_run|release)[ \t]*:"
        ),
        "publishing or release operation": (
            r"\b(?:cargo\s+publish|npm\s+publish|pnpm\s+publish|"
            r"yarn\s+(?:npm\s+)?publish|gh\s+(?:release|api|pr)|"
            r"git\s+(?:push|tag|commit)|docker\s+(?:login|push)|"
            r"twine\s+upload|gem\s+push|nix\s+copy|release\s+create)\b|"
            r"^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*"
            r"[^\s#]*(?:release|publish|attest)"
        ),
        "upstream synchronization": (
            r"\b(?:git\s+(?:pull|merge|rebase)|gh\s+repo\s+sync|"
            r"git\s+remote\s+add\s+upstream)\b|"
            r"^[ \t]+repository[ \t]*:"
        ),
        "real fleet access": (
            r"\b(?:fleet|ocelot|siberian|sandcat|margay|tailscale|"
            r"wireguard|ssh|scp|rsync)\b"
        ),
        "self-hosted runner": r"\bself-hosted\b",
        "runner group": r"^[ \t]+runs-on[ \t]*:[ \t]*(?:\{|$)",
        "job or service container": r"^[ \t]*(?:container|services)[ \t]*:",
        "YAML indirection": (
            r"^[ \t]*<<[ \t]*:|:[ \t]*[&*][A-Za-z0-9_-]+[ \t]*(?:#.*)?$"
        ),
        "quoted workflow control key": (
            r"^[ \t]*['\"](?:on|jobs|if|runs-on|permissions|uses|"
            r"environment|secrets)['\"]\s*:"
        ),
    }
    for description, pattern in forbidden.items():
        require(
            re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE) is None,
            f"integration workflow contains {description}",
        )


def verify_integration_workflow(
    manifest: dict[str, Any], text: str, path: Path = INTEGRATION_WORKFLOW
) -> None:
    normalized = text.replace("\r\n", "\n")
    top_level_keys = re.findall(r"(?m)^([A-Za-z][A-Za-z0-9_-]*)\s*:", normalized)
    require(
        top_level_keys == ["name", "on", "permissions", "concurrency", "jobs"],
        "integration workflow top-level structure drifted",
    )

    on_entries = list(re.finditer(r"(?m)^on:[ \t]*$", normalized))
    permission_entries = list(re.finditer(r"(?m)^permissions:[ \t]*$", normalized))
    require(
        len(on_entries) == 1
        and len(permission_entries) == 1
        and on_entries[0].start() < permission_entries[0].start(),
        "integration workflow trigger or permissions block is malformed",
    )
    trigger_block = normalized[
        on_entries[0].start() : permission_entries[0].start()
    ].strip()
    require(
        trigger_block == EXPECTED_TRIGGER_BLOCK,
        "integration workflow trigger set, default branch, or daily canary drifted",
    )
    permission_lines = re.findall(r"(?m)^[ \t]*permissions[ \t]*:.*$", normalized)
    require(
        permission_lines == ["permissions:"]
        and "\npermissions:\n  contents: read\n\nconcurrency:\n" in normalized,
        "integration workflow permissions must be exactly top-level contents: read",
    )

    verify_integration_boundaries(normalized)
    require(
        "AxiomLayer/" not in normalized,
        "integration workflow uses noncanonical machine repository casing",
    )

    blocks = workflow_job_blocks(normalized)
    require(
        tuple(blocks)
        == ("contract-and-integrity", "native-build-test", "promotion-gate"),
        "integration workflow evidence job set drifted",
    )
    for name, block in blocks.items():
        condition = workflow_job_condition(block)
        expected = (
            "always()" if name == "promotion-gate" else TRUSTED_WORKFLOW_CONDITION
        )
        require(
            condition is not None
            and compact_expression(condition) == compact_expression(expected),
            f"integration job {name} lost its exact event and identity firewall",
        )
    require(
        re.findall(r"(?m)^    needs:\s*(.*?)\s*$", blocks["native-build-test"])
        == ["contract-and-integrity"],
        "native build must depend on the integrity contract",
    )

    for authority_line in (
        'test "$AXIOM_REPOSITORY" = "axiomlayer/ripgrep"',
        'test "$DEFAULT_BRANCH" = "master"',
        'test "$BASE_REPOSITORY" = "axiomlayer/ripgrep"',
        'test "$HEAD_REPOSITORY" = "axiomlayer/ripgrep"',
        'test "$BASE_REF" = "master"',
        'test "$REF" = "refs/pull/$PR_NUMBER/merge"',
        'test "$WORKFLOW_REF" = "axiomlayer/ripgrep/.github/workflows/axiomlayer-integration.yml@refs/pull/$PR_NUMBER/merge"',
        'test "$REF" = "refs/heads/master"',
        'test "$REF_PROTECTED" = "true"',
        'test "$WORKFLOW_REF" = "axiomlayer/ripgrep/.github/workflows/axiomlayer-integration.yml@refs/heads/master"',
        'test "$CONTRACT_RESULT" = success',
        'test "$NATIVE_RESULT" = success',
    ):
        require(
            normalized.count(authority_line) == 1,
            f"integration terminal authority drifted: {authority_line}",
        )

    job_runners = tuple(re.findall(r"(?m)^    runs-on:\s*(.*?)\s*$", normalized))
    require(
        job_runners == EXPECTED_JOB_RUNNERS,
        "integration workflow changed its exact hosted job runners",
    )
    matrix_runners = tuple(
        re.findall(r"(?m)^            runner:\s*(.*?)\s*$", normalized)
    )
    require(
        matrix_runners == EXPECTED_MATRIX_RUNNERS,
        "integration workflow changed its exact hosted runner matrix",
    )
    require(
        "-latest" not in normalized,
        "integration workflow uses a floating hosted runner image",
    )

    active_actions = []
    for line in normalized.splitlines():
        match = REMOTE_USE.fullmatch(line)
        if match is not None:
            active_actions.append(match.group(2))
    expected_actions = manifest["workflowActions"]
    require(
        active_actions
        == [
            f"actions/checkout@{expected_actions['actions/checkout']}",
            f"actions/checkout@{expected_actions['actions/checkout']}",
            f"dtolnay/rust-toolchain@{expected_actions['dtolnay/rust-toolchain']}",
        ],
        "integration workflow action inventory drifted",
    )
    verify_action_references(normalized, path, expected_actions)

    checkout_blocks = checkout_step_blocks(normalized)
    require(len(checkout_blocks) == 2, "integration checkout count drifted")
    for indentation, block in checkout_blocks:
        require(
            len(re.findall(rf"(?m)^ {{{indentation}}}with:\s*$", block)) == 1,
            "actions/checkout must declare one with mapping",
        )
        for key, expected in (
            ("clean", "true"),
            ("fetch-depth", "0"),
            ("persist-credentials", "false"),
            ("ref", "${{ github.sha }}"),
        ):
            values = re.findall(rf"(?m)^\s*{re.escape(key)}:\s*(.*?)\s*$", block)
            require(
                values == [expected]
                and re.search(
                    rf"(?m)^ {{{indentation + 2}}}{re.escape(key)}:\s*"
                    rf"{re.escape(expected)}\s*$",
                    block,
                )
                is not None,
                f"actions/checkout must set {key}: {expected} in its with mapping",
            )

    evidence_counts = {
        "integration/axiomlayer/verify.py validate": 1,
        "integration/axiomlayer/verify.py verify-source": 2,
        "integration/axiomlayer/verify.py verify-workflows": 1,
        "-m unittest -v integration/axiomlayer/test_verify.py": 1,
        "integration/axiomlayer/verify.py verify-all-assets": 1,
        "integration/axiomlayer/verify.py materialize-source": 1,
        "/bin/sh integration/axiomlayer/install-nix-ci.sh": 1,
        "/nix/var/nix/profiles/default/bin/nix-build integration/axiomlayer/default.nix": 1,
        "cargo test --locked --workspace --features pcre2": 1,
        "cargo build --locked --profile release-lto --features pcre2": 1,
        "integration/axiomlayer/verify.py verify-asset": 1,
        "--execute": 1,
        "--receipt": 1,
    }
    for fragment, expected_count in evidence_counts.items():
        require(
            normalized.count(fragment) == expected_count,
            f"integration workflow evidence drifted: {fragment}",
        )
    require(
        normalized.count("/bin/sh integration/axiomlayer/install-nix-ci.sh") == 1,
        "native Nix jobs must use the reviewed bootstrap wrapper",
    )
    for fragment in (
        'HOME="$RUNNER_TEMP/nix-bootstrap-home"',
        'PATH="/usr/bin:/bin:/usr/sbin:/sbin"',
        'HOME="$RUNNER_TEMP/nix-build-home"',
        'PATH="/nix/var/nix/profiles/default/bin:/usr/bin:/bin:/usr/sbin:/sbin"',
        'TMPDIR="$RUNNER_TEMP/nix-build-tmp"',
    ):
        require(
            normalized.count(fragment) == 1,
            f"hosted Nix sterile environment drifted: {fragment}",
        )
    require(
        normalized.count("          /usr/bin/env -i \\") == 2,
        "Nix installer and build must each start with an empty environment",
    )
    require(
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        == manifest["workflowFirewall"]["activeWorkflow"]["sha256"],
        "active workflow digest drift",
    )


def read_git_blob(root: Path, commit: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise VerificationError(f"cannot read upstream workflow {path}: {detail}")
    return result.stdout


def git_tree_inventory(
    root: Path, commit: str, source_roots: list[str]
) -> dict[str, str]:
    listing = run_git(
        "ls-tree",
        "-r",
        "--full-tree",
        commit,
        "--",
        *source_roots,
        root=root,
    )
    inventory: dict[str, str] = {}
    for line in listing.splitlines():
        metadata, separator, path = line.partition("\t")
        require(bool(separator), f"cannot parse upstream tree entry: {line}")
        fields = metadata.split()
        require(len(fields) == 3, f"cannot parse upstream tree metadata: {line}")
        mode, kind, _object_id = fields
        require(kind == "blob", f"unsupported upstream workflow object: {path}")
        require(path not in inventory, f"duplicate upstream workflow path: {path}")
        inventory[path] = mode
    require(inventory, "upstream workflow baseline is empty")
    return inventory


def verify_workflow_archive(
    manifest: dict[str, Any],
    root: Path = REPOSITORY_ROOT,
    *,
    provenance_root: Path = REPOSITORY_ROOT,
) -> None:
    validate_manifest(manifest)
    archive = manifest["workflowFirewall"]["upstreamArchive"]
    entries = archive["files"]
    source_inventory = git_tree_inventory(
        provenance_root, archive["commit"], archive["sourceRoots"]
    )
    expected_source_inventory = {
        entry["sourcePath"]: entry["gitMode"] for entry in entries
    }
    require(
        source_inventory == expected_source_inventory,
        "upstream workflow baseline and archive manifest inventories disagree",
    )

    archive_root = root / archive["archiveRoot"]
    require(
        archive_root.is_dir() and not archive_root.is_symlink(),
        "workflow archive root is missing or linked",
    )
    actual_archive_paths: list[str] = []
    for candidate in archive_root.rglob("*"):
        require(
            not candidate.is_symlink(),
            f"workflow archive contains a symlink: {candidate}",
        )
        if candidate.is_file():
            actual_archive_paths.append(candidate.relative_to(root).as_posix())
    expected_archive_paths = [entry["archivePath"] for entry in entries]
    require(
        sorted(actual_archive_paths) == expected_archive_paths,
        "workflow archive contains a missing, extra, or renamed file",
    )

    for entry in entries:
        source_path = entry["sourcePath"]
        archive_path = root / entry["archivePath"]
        archived = archive_path.read_bytes()
        upstream = read_git_blob(provenance_root, archive["commit"], source_path)
        archive_permissions = stat.S_IMODE(archive_path.stat().st_mode)
        expected_permissions = 0o755 if entry["gitMode"] == "100755" else 0o644
        require(
            archive_permissions == expected_permissions,
            f"workflow archive mode drift: {source_path}",
        )
        digest = hashlib.sha256(archived).hexdigest()
        require(
            digest == entry["sha256"],
            f"workflow archive digest drift: {source_path}",
        )
        require(
            hashlib.sha256(upstream).hexdigest() == entry["sha256"],
            f"workflow baseline digest drift: {source_path}",
        )
        require(
            archived == upstream,
            f"workflow archive is not byte-identical to upstream: {source_path}",
        )


def verify_active_workflow_set(manifest: dict[str, Any], root: Path) -> Path:
    workflow_root = root / ".github" / "workflows"
    require(
        workflow_root.is_dir() and not workflow_root.is_symlink(),
        ".github/workflows must be a real directory",
    )
    actual_files: list[str] = []
    for candidate in workflow_root.rglob("*"):
        require(
            not candidate.is_symlink(),
            f"executable workflow surface contains a symlink: {candidate}",
        )
        if candidate.is_file():
            actual_files.append(candidate.relative_to(root).as_posix())
    actual_files.sort()
    active_path = manifest["workflowFirewall"]["activeWorkflow"]["path"]
    require(
        actual_files == [active_path],
        "the AxiomLayer integration must be the only executable workflow file",
    )
    path = root / active_path
    require(path.is_file() and not path.is_symlink(), "active workflow is missing")
    return path


def verify_workflows(manifest: dict[str, Any], root: Path = REPOSITORY_ROOT) -> None:
    validate_manifest(manifest)
    integration_path = verify_active_workflow_set(manifest, root)
    workflow_paths = [integration_path]
    expected_actions = manifest["workflowActions"]
    seen_actions: set[str] = set()
    for path in workflow_paths:
        text = path.read_text(encoding="utf-8")
        seen_actions.update(verify_action_references(text, path, expected_actions))
    require(
        set(expected_actions) == seen_actions,
        "workflow action use and the reviewed allowlist disagree",
    )

    require(
        discover_axiomlayer_workflow(workflow_paths) == integration_path,
        "active AxiomLayer workflow discovery drifted",
    )
    integration_text = integration_path.read_text(encoding="utf-8")
    verify_integration_workflow(manifest, integration_text, integration_path)
    verify_nix_bootstrap(
        manifest, root / "integration" / "axiomlayer" / "install-nix-ci.sh"
    )
    verify_nix_expression(manifest, root / "integration" / "axiomlayer" / "default.nix")
    verify_workflow_archive(manifest, root, provenance_root=root)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_nix_bootstrap_text(nix: dict[str, Any], text: str) -> None:
    for required in (
        f"NIX_VERSION={nix['version']}",
        f"INSTALLER_URL={nix['installerUrl']}",
        f"INSTALLER_SHA256={nix['installerSha256']}",
        "SYSTEM_PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "PATH=$SYSTEM_PATH",
        "umask 077",
        "mktemp -d /tmp/axiom-nix-ci.XXXXXXXX",
        "env -i",
        "--no-channel-add --no-modify-profile",
    ):
        require(required in text, f"Nix bootstrap lost required boundary: {required}")
    for digest in nix["binaryTarballSha256"].values():
        require(digest in text, "Nix bootstrap lost a pinned platform digest")
    for forbidden in (
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "github.token",
        "github_access_token",
        "${TMPDIR:-/tmp}",
        'PATH="$PATH"',
    ):
        require(
            forbidden not in text,
            f"Nix bootstrap references a live credential surface: {forbidden}",
        )


def verify_nix_bootstrap(manifest: dict[str, Any], path: Path) -> None:
    validate_manifest(manifest)
    nix = manifest["nix"]
    text = path.read_text(encoding="utf-8")
    require(
        sha256_file(path) == nix["wrapperSha256"],
        "Nix bootstrap wrapper digest mismatch",
    )
    verify_nix_bootstrap_text(nix, text)


def verify_nix_expression(manifest: dict[str, Any], path: Path) -> None:
    validate_manifest(manifest)
    require(
        path.is_file() and not path.is_symlink(), "Nix expression is missing or linked"
    )
    nix = manifest["nix"]
    require(
        sha256_file(path) == nix["expressionSha256"],
        "Nix expression digest mismatch",
    )
    text = path.read_text(encoding="utf-8")
    for value in (
        manifest["promotion"]["version"],
        nix["nixpkgs"]["url"],
        nix["nixpkgs"]["narHash"],
    ):
        require(value in text, f"Nix expression lost reviewed value: {value}")


def assert_file_digest(path: Path, expected: str, label: str) -> None:
    actual = sha256_file(path)
    if actual != expected:
        raise VerificationError(
            f"{label} digest mismatch: expected {expected}, got {actual}"
        )


def safe_destination(root: Path, member_name: str) -> Path:
    require(member_name != "", "archive member name is empty")
    require("\\" not in member_name, f"archive path uses a backslash: {member_name}")
    member = PurePosixPath(member_name)
    require(not member.is_absolute(), f"absolute archive path: {member_name}")
    require(".." not in member.parts, f"archive path traverses upward: {member_name}")
    normalized = member.as_posix()
    require(
        member_name in {normalized, f"{normalized}/"},
        f"archive path is not normalized: {member_name}",
    )
    destination = root.joinpath(*member.parts).resolve()
    root_resolved = root.resolve()
    require(
        destination == root_resolved or root_resolved in destination.parents,
        f"archive path escapes extraction root: {member_name}",
    )
    return destination


def extract_archive(archive: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    seen_destinations: set[Path] = set()
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zipped:
            for info in zipped.infolist():
                target = safe_destination(destination, info.filename)
                require(
                    target not in seen_destinations,
                    f"duplicate archive path: {info.filename}",
                )
                seen_destinations.add(target)
                mode = (info.external_attr >> 16) & 0o170000
                require(
                    mode in {0, stat.S_IFREG, stat.S_IFDIR},
                    f"archive special member is forbidden: {info.filename}",
                )
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zipped.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                permissions = (info.external_attr >> 16) & 0o777
                if permissions:
                    target.chmod(permissions)
        return
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as tarred:
            for member in tarred.getmembers():
                target = safe_destination(destination, member.name)
                require(
                    target not in seen_destinations,
                    f"duplicate archive path: {member.name}",
                )
                seen_destinations.add(target)
                require(
                    not (member.issym() or member.islnk()),
                    f"archive link is forbidden: {member.name}",
                )
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                require(
                    member.isfile(),
                    f"special archive member is forbidden: {member.name}",
                )
                source = tarred.extractfile(member)
                require(
                    source is not None, f"cannot read archive member: {member.name}"
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o777)
        return
    raise VerificationError(f"unsupported archive format: {archive.name}")


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url, headers={"User-Agent": "axiomlayer-ripgrep-ci/1"}
    )
    partial = destination.with_suffix(destination.suffix + ".partial")
    if partial.exists():
        partial.unlink()
    try:
        with (
            urllib.request.urlopen(request, timeout=90) as response,
            partial.open("wb") as output,
        ):
            shutil.copyfileobj(response, output)
        os.replace(partial, destination)
    except Exception:
        if partial.exists():
            partial.unlink()
        raise


def detected_target() -> str:
    system = platform.system().lower()
    system = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(
        system, system
    )
    machine = platform.machine().lower()
    architecture = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(machine, machine)
    return f"{system}-{architecture}"


def verify_asset(
    manifest: dict[str, Any],
    target: str,
    directory: Path,
    execute: bool = False,
    receipt_path: Path | None = None,
) -> dict[str, Any]:
    validate_manifest(manifest)
    require(target in manifest["targets"], f"unknown target: {target}")
    spec = manifest["targets"][target]
    directory.mkdir(parents=True, exist_ok=True)
    require(
        directory.is_dir() and not directory.is_symlink(),
        f"{target}: artifact directory is missing or linked",
    )
    archive = directory / spec["archiveName"]
    require(not archive.is_symlink(), f"{target}: archive cache entry is linked")
    if not archive.exists() or sha256_file(archive) != spec["archiveSha256"]:
        download(spec["archiveUrl"], archive)
    require(
        archive.stat().st_size == spec["archiveBytes"],
        f"{target}: archive size mismatch",
    )
    assert_file_digest(archive, spec["archiveSha256"], f"{target} archive")
    extracted = directory / f"extracted-{target}"
    extract_archive(archive, extracted)
    binary = extracted / spec["archiveRoot"] / spec["binary"]
    require(binary.is_file(), f"{target}: extracted binary is missing")
    assert_file_digest(binary, spec["binarySha256"], f"{target} binary")

    version_output: str | None = None
    host = detected_target()
    if execute:
        require(host == target, f"native execution requested for {target} on {host}")
        if system_is_unix(target):
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        proc = subprocess.run(
            [str(binary), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        require(proc.returncode == 0, f"{target}: rg --version failed")
        version_output = proc.stdout.strip().splitlines()[0]
        require(
            version_output.startswith(f"ripgrep {manifest['promotion']['version']}"),
            f"{target}: unexpected version output: {version_output}",
        )

    receipt = {
        "schema": "axiomlayer-ripgrep-integration-receipt-v1",
        "candidateId": manifest["promotion"]["candidateId"],
        "sourceCommit": manifest["promotion"]["commit"],
        "target": target,
        "runner": spec["runner"],
        "buildMode": spec["buildMode"],
        "detectedHost": host,
        "archiveSha256": spec["archiveSha256"],
        "binarySha256": spec["binarySha256"],
        "nativeExecuted": execute,
        "versionOutput": version_output,
    }
    if receipt_path is not None:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def system_is_unix(target: str) -> bool:
    return target.startswith("darwin-") or target.startswith("linux-")


def materialize_source(
    manifest: dict[str, Any], destination: Path, root: Path = REPOSITORY_ROOT
) -> None:
    verify_source(manifest, root=root)
    require(not destination.exists(), f"destination already exists: {destination}")
    run_git(
        "worktree",
        "add",
        "--detach",
        str(destination),
        manifest["promotion"]["commit"],
        root=root,
    )
    actual = run_git("rev-parse", "HEAD", root=destination)
    require(
        actual == manifest["promotion"]["commit"], "materialized source is not pinned"
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "verify-source", "verify-workflows"):
        subparsers.add_parser(name)
    materialize = subparsers.add_parser("materialize-source")
    materialize.add_argument("--destination", type=Path, required=True)
    asset = subparsers.add_parser("verify-asset")
    asset.add_argument("--target", required=True)
    asset.add_argument("--directory", type=Path, required=True)
    asset.add_argument("--execute", action="store_true")
    asset.add_argument("--receipt", type=Path)
    all_assets = subparsers.add_parser("verify-all-assets")
    all_assets.add_argument("--directory", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        manifest = load_manifest(args.manifest)
        if args.command == "validate":
            validate_manifest(manifest)
        elif args.command == "verify-source":
            verify_source(manifest)
        elif args.command == "verify-workflows":
            verify_workflows(manifest)
        elif args.command == "materialize-source":
            materialize_source(manifest, args.destination)
        elif args.command == "verify-asset":
            receipt = verify_asset(
                manifest,
                args.target,
                args.directory,
                execute=args.execute,
                receipt_path=args.receipt,
            )
            print(json.dumps(receipt, sort_keys=True))
        elif args.command == "verify-all-assets":
            receipts = [
                verify_asset(manifest, target, args.directory)
                for target in sorted(manifest["targets"])
            ]
            print(json.dumps(receipts, sort_keys=True))
        else:
            raise AssertionError(args.command)
    except (
        OSError,
        VerificationError,
        urllib.error.URLError,
        zipfile.BadZipFile,
        tarfile.TarError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
