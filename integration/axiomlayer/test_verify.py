#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "axiom_ripgrep_verify", HERE / "verify.py"
)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = verify.load_manifest()
        cls.workflow = (verify.REPOSITORY_ROOT / verify.INTEGRATION_WORKFLOW).read_text(
            encoding="utf-8"
        )

    def assert_workflow_rejected(self, candidate: str, message: str) -> None:
        self.assertNotEqual(self.workflow, candidate)
        with self.assertRaisesRegex(verify.VerificationError, message):
            verify.verify_integration_workflow(self.manifest, candidate)

    def run_terminal_gate(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        block = verify.workflow_job_blocks(self.workflow)["promotion-gate"]
        marker = "        run: |\n"
        self.assertEqual(block.count(marker), 1)
        script = textwrap.dedent(block.split(marker, 1)[1])
        environment = {
            "PATH": "/usr/bin:/bin",
            "EVENT_NAME": "pull_request",
            "AXIOM_REPOSITORY": "axiomlayer/ripgrep",
            "DEFAULT_BRANCH": "master",
            "BASE_REPOSITORY": "axiomlayer/ripgrep",
            "HEAD_REPOSITORY": "axiomlayer/ripgrep",
            "BASE_REF": "master",
            "REF": "refs/pull/41/merge",
            "REF_PROTECTED": "false",
            "WORKFLOW_REF": (
                "axiomlayer/ripgrep/.github/workflows/"
                "axiomlayer-integration.yml@refs/pull/41/merge"
            ),
            "PR_NUMBER": "41",
            "CONTRACT_RESULT": "success",
            "NATIVE_RESULT": "success",
        }
        environment.update(overrides)
        return subprocess.run(
            ["/bin/sh", "-eu"],
            input=script,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @contextmanager
    def archive_fixture(self) -> Iterator[tuple[Path, dict]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = copy.deepcopy(self.manifest)
            entries = manifest["workflowFirewall"]["upstreamArchive"]["files"]
            for entry in entries:
                source = verify.REPOSITORY_ROOT / entry["archivePath"]
                destination = root / entry["archivePath"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            yield root, manifest

    def test_manifest_is_complete(self) -> None:
        verify.validate_manifest(self.manifest)

    def test_dotfiles_authority_identity_is_immutable(self) -> None:
        mutations = {
            "authority": "axiomlayer/dotfiles#999",
            "authorityCommit": "0" * 40,
            "authorityRuntimeManifestPath": "integration/authority.json",
            "authorityRuntimeManifestSha256": "0" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                bad = copy.deepcopy(self.manifest)
                bad["promotion"][field] = value
                with self.assertRaisesRegex(
                    verify.VerificationError, "authority|runtime manifest"
                ):
                    verify.validate_manifest(bad)

    def test_vendored_dotfiles_authority_binds_every_ripgrep_pin(self) -> None:
        verify.verify_authority_manifest(self.manifest)
        bad = copy.deepcopy(self.manifest)
        bad["targets"]["windows-aarch64"]["archiveSha256"] = "0" * 64
        with self.assertRaisesRegex(verify.VerificationError, "diverges"):
            verify.verify_authority_manifest(bad)

    def test_vendored_dotfiles_authority_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = verify.REPOSITORY_ROOT / verify.AUTHORITY_RUNTIME_MANIFEST
            destination = root / verify.AUTHORITY_RUNTIME_MANIFEST
            destination.parent.mkdir(parents=True)
            shutil.copy2(source, destination)
            destination.write_bytes(destination.read_bytes() + b"\n")
            with self.assertRaisesRegex(verify.VerificationError, "digest drifted"):
                verify.verify_authority_manifest(self.manifest, root)

    def test_manifest_refuses_extra_fields_and_target_metadata_drift(self) -> None:
        bad = copy.deepcopy(self.manifest)
        bad["unreviewed"] = True
        with self.assertRaisesRegex(
            verify.VerificationError, "manifest fields drifted"
        ):
            verify.validate_manifest(bad)

        for field, value in (
            ("archiveName", "../outside.tar.gz"),
            ("archiveRoot", "../outside"),
            ("runner", "self-hosted"),
            ("archiveBytes", True),
        ):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.manifest)
                bad["targets"]["darwin-aarch64"][field] = value
                with self.assertRaises(verify.VerificationError):
                    verify.validate_manifest(bad)

    def test_promoted_source_is_exact(self) -> None:
        verify.verify_source(self.manifest)

    def test_only_axiomlayer_workflow_is_active_pinned_and_read_only(self) -> None:
        verify.verify_workflows(self.manifest)

    def test_upstream_workflow_archive_is_complete_and_byte_identical(self) -> None:
        archive = self.manifest["workflowFirewall"]["upstreamArchive"]
        self.assertEqual(
            [entry["sourcePath"] for entry in archive["files"]],
            [
                ".github/workflows/ci.yml",
                ".github/workflows/release.yml",
                "ci/sha256-releases",
                "ci/test-complete",
                "ci/ubuntu-install-packages",
                "ci/utils.sh",
            ],
        )
        verify.verify_workflow_archive(self.manifest)

    def test_missing_extra_and_renamed_archive_files_fail_closed(self) -> None:
        for mutation in ("missing", "extra", "renamed"):
            with (
                self.subTest(mutation=mutation),
                self.archive_fixture() as (
                    root,
                    manifest,
                ),
            ):
                archive = manifest["workflowFirewall"]["upstreamArchive"]
                target = root / archive["files"][-1]["archivePath"]
                if mutation == "missing":
                    target.unlink()
                elif mutation == "extra":
                    (target.parent / "unexpected-support.txt").write_text(
                        "unexpected\n", encoding="utf-8"
                    )
                else:
                    target.rename(target.with_name("renamed.yml"))
                with self.assertRaisesRegex(
                    verify.VerificationError, "missing, extra, or renamed"
                ):
                    verify.verify_workflow_archive(
                        manifest,
                        root,
                        provenance_root=verify.REPOSITORY_ROOT,
                    )

    def test_archive_symlink_fails_closed(self) -> None:
        with self.archive_fixture() as (root, manifest):
            entry = manifest["workflowFirewall"]["upstreamArchive"]["files"][-1]
            target = root / entry["archivePath"]
            target.unlink()
            target.symlink_to(verify.REPOSITORY_ROOT / entry["archivePath"])
            with self.assertRaisesRegex(verify.VerificationError, "symlink"):
                verify.verify_workflow_archive(
                    manifest,
                    root,
                    provenance_root=verify.REPOSITORY_ROOT,
                )

    def test_archive_tamper_fails_even_if_manifest_is_rehashed(self) -> None:
        for source_path in (".github/workflows/ci.yml", "ci/test-complete"):
            for rehash in (False, True):
                with (
                    self.subTest(source_path=source_path, rehash=rehash),
                    self.archive_fixture() as (
                        root,
                        manifest,
                    ),
                ):
                    entries = manifest["workflowFirewall"]["upstreamArchive"]["files"]
                    entry = next(
                        item for item in entries if item["sourcePath"] == source_path
                    )
                    target = root / entry["archivePath"]
                    target.write_bytes(target.read_bytes() + b"# tampered\n")
                    if rehash:
                        entry["sha256"] = hashlib.sha256(
                            target.read_bytes()
                        ).hexdigest()
                    with self.assertRaisesRegex(
                        verify.VerificationError,
                        "archive digest drift|baseline digest drift|not byte-identical",
                    ):
                        verify.verify_workflow_archive(
                            manifest,
                            root,
                            provenance_root=verify.REPOSITORY_ROOT,
                        )

    def test_archive_mode_drift_fails_closed(self) -> None:
        with self.archive_fixture() as (root, manifest):
            entries = manifest["workflowFirewall"]["upstreamArchive"]["files"]
            entry = next(
                item for item in entries if item["sourcePath"] == "ci/sha256-releases"
            )
            target = root / entry["archivePath"]
            target.chmod(target.stat().st_mode & ~0o111)
            with self.assertRaisesRegex(verify.VerificationError, "mode drift"):
                verify.verify_workflow_archive(
                    manifest,
                    root,
                    provenance_root=verify.REPOSITORY_ROOT,
                )

    def test_extra_executable_workflow_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / verify.INTEGRATION_WORKFLOW
            active.parent.mkdir(parents=True)
            shutil.copy2(verify.REPOSITORY_ROOT / verify.INTEGRATION_WORKFLOW, active)
            (active.parent / "release.yml").write_text(
                "name: release\non: [push]\njobs: {}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                verify.VerificationError, "only executable workflow"
            ):
                verify.verify_active_workflow_set(self.manifest, root)

    def test_exact_workflow_contexts_are_accepted(self) -> None:
        accepted = (
            {
                "event_name": "pull_request",
                "ref": "refs/pull/41/merge",
                "base_ref": "master",
                "base_repository": "axiomlayer/ripgrep",
                "head_repository": "axiomlayer/ripgrep",
                "event_number": 41,
                "workflow_ref": (
                    "axiomlayer/ripgrep/.github/workflows/"
                    "axiomlayer-integration.yml@refs/pull/41/merge"
                ),
            },
            {
                "event_name": "push",
                "ref": "refs/heads/master",
                "ref_protected": True,
                "workflow_ref": verify.INTEGRATION_WORKFLOW_REF,
            },
            {
                "event_name": "schedule",
                "ref": "refs/heads/master",
                "ref_protected": True,
                "workflow_ref": verify.INTEGRATION_WORKFLOW_REF,
            },
            {
                "event_name": "workflow_dispatch",
                "ref": "refs/heads/master",
                "ref_protected": True,
                "workflow_ref": verify.INTEGRATION_WORKFLOW_REF,
            },
        )
        for context in accepted:
            with self.subTest(event=context["event_name"]):
                self.assertTrue(
                    verify.workflow_context_allowed(
                        verify.FORK_REPOSITORY,
                        verify.FORK_DEFAULT_BRANCH,
                        **context,
                    )
                )

    def test_uppercase_machine_owner_is_refused(self) -> None:
        self.assertFalse(
            verify.workflow_context_allowed(
                "AxiomLayer/ripgrep",
                "master",
                "push",
                "refs/heads/master",
                ref_protected=True,
            )
        )
        self.assert_workflow_rejected(
            self.workflow.replace(
                "github.repository == 'axiomlayer/ripgrep'",
                "github.repository == 'AxiomLayer/ripgrep'",
                1,
            ),
            "noncanonical machine repository casing",
        )

    def test_pull_request_must_use_the_numbered_default_branch_merge_ref(self) -> None:
        for ref, base_ref, event_number in (
            ("refs/pull/41/head", "master", 41),
            ("refs/pull/41/merge", "feature/unsafe", 41),
            ("refs/pull/not-a-number/merge", "master", None),
        ):
            with self.subTest(ref=ref, base_ref=base_ref):
                self.assertFalse(
                    verify.workflow_context_allowed(
                        "axiomlayer/ripgrep",
                        "master",
                        "pull_request",
                        ref,
                        base_ref=base_ref,
                        base_repository="axiomlayer/ripgrep",
                        head_repository="axiomlayer/ripgrep",
                        event_number=event_number,
                        workflow_ref=(
                            "axiomlayer/ripgrep/.github/workflows/"
                            f"axiomlayer-integration.yml@{ref}"
                        ),
                    )
                )
        self.assert_workflow_rejected(
            self.workflow.replace(
                "format('refs/pull/{0}/merge', github.event.number)",
                "format('refs/pull/{0}/head', github.event.number)",
                1,
            ),
            "event and identity firewall",
        )

    def test_pull_request_must_come_from_the_exact_fork_repository(self) -> None:
        for base_repository, head_repository in (
            ("BurntSushi/ripgrep", "axiomlayer/ripgrep"),
            ("axiomlayer/ripgrep", "contributor/ripgrep"),
            ("AxiomLayer/ripgrep", "axiomlayer/ripgrep"),
        ):
            with self.subTest(
                base_repository=base_repository,
                head_repository=head_repository,
            ):
                self.assertFalse(
                    verify.workflow_context_allowed(
                        "axiomlayer/ripgrep",
                        "master",
                        "pull_request",
                        "refs/pull/41/merge",
                        base_ref="master",
                        base_repository=base_repository,
                        head_repository=head_repository,
                        event_number=41,
                        workflow_ref=(
                            "axiomlayer/ripgrep/.github/workflows/"
                            "axiomlayer-integration.yml@refs/pull/41/merge"
                        ),
                    )
                )
        self.assert_workflow_rejected(
            self.workflow.replace(
                "github.event.pull_request.head.repo.full_name == 'axiomlayer/ripgrep'",
                "github.event.pull_request.head.repo.full_name != ''",
                1,
            ),
            "event and identity firewall",
        )

    def test_feature_manual_ref_is_refused(self) -> None:
        self.assertFalse(
            verify.workflow_context_allowed(
                "axiomlayer/ripgrep",
                "master",
                "workflow_dispatch",
                "refs/heads/feature/unsafe",
                ref_protected=True,
                workflow_ref=verify.INTEGRATION_WORKFLOW_REF,
            )
        )
        self.assert_workflow_rejected(
            self.workflow.replace(
                "github.event_name == 'workflow_dispatch' &&\n"
                "      github.ref == 'refs/heads/master'",
                "github.event_name == 'workflow_dispatch' &&\n"
                "      github.ref == 'refs/heads/feature/unsafe'",
                1,
            ),
            "event and identity firewall",
        )

    def test_unprotected_default_ref_is_refused(self) -> None:
        for event_name in ("push", "schedule", "workflow_dispatch"):
            with self.subTest(event=event_name):
                self.assertFalse(
                    verify.workflow_context_allowed(
                        "axiomlayer/ripgrep",
                        "master",
                        event_name,
                        "refs/heads/master",
                        ref_protected=False,
                        workflow_ref=verify.INTEGRATION_WORKFLOW_REF,
                    )
                )
        self.assert_workflow_rejected(
            self.workflow.replace(
                "github.ref_protected == true",
                "github.ref_protected == false",
                1,
            ),
            "event and identity firewall",
        )

    def test_alternate_workflow_ref_is_refused(self) -> None:
        alternate = "axiomlayer/ripgrep/.github/workflows/release.yml@refs/heads/master"
        for event_name in ("push", "schedule", "workflow_dispatch"):
            with self.subTest(event=event_name):
                self.assertFalse(
                    verify.workflow_context_allowed(
                        "axiomlayer/ripgrep",
                        "master",
                        event_name,
                        "refs/heads/master",
                        ref_protected=True,
                        workflow_ref=alternate,
                    )
                )
        self.assert_workflow_rejected(
            self.workflow.replace(verify.INTEGRATION_WORKFLOW_REF, alternate, 1),
            "event and identity firewall",
        )

    def test_terminal_gate_cannot_green_skip_an_untrusted_source(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("    if: always()\n", "    if: success()\n", 1),
            "event and identity firewall",
        )
        self.assertEqual(self.run_terminal_gate().returncode, 0)
        invalid_sources = (
            {"AXIOM_REPOSITORY": "contributor/ripgrep"},
            {"DEFAULT_BRANCH": "feature/unsafe"},
            {"BASE_REPOSITORY": "BurntSushi/ripgrep"},
            {"HEAD_REPOSITORY": "contributor/ripgrep"},
            {"BASE_REF": "feature/unsafe"},
            {"REF": "refs/pull/41/head"},
            {
                "WORKFLOW_REF": (
                    "axiomlayer/ripgrep/.github/workflows/"
                    "axiomlayer-integration.yml@refs/heads/master"
                )
            },
            {"CONTRACT_RESULT": "skipped"},
            {"NATIVE_RESULT": "failure"},
        )
        for environment in invalid_sources:
            with self.subTest(environment=environment):
                self.assertNotEqual(
                    self.run_terminal_gate(**environment).returncode,
                    0,
                )

    def test_native_build_waits_for_the_integrity_contract(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("    needs: contract-and-integrity\n", "", 1),
            "depend on the integrity contract",
        )

    def test_terminal_gate_rechecks_exact_pull_request_identity(self) -> None:
        mutations = (
            (
                'test "$REF" = "refs/pull/$PR_NUMBER/merge"',
                'test "$REF" = "refs/pull/unsafe/merge"',
            ),
            (
                'test "$HEAD_REPOSITORY" = "axiomlayer/ripgrep"',
                'test "$HEAD_REPOSITORY" != ""',
            ),
            (
                'test "$BASE_REPOSITORY" = "axiomlayer/ripgrep"',
                'test "$BASE_REPOSITORY" != ""',
            ),
        )
        for original, replacement in mutations:
            with self.subTest(original=original):
                self.assert_workflow_rejected(
                    self.workflow.replace(original, replacement, 1),
                    "terminal authority drifted",
                )

    def test_active_workflow_digest_tamper_fails_closed(self) -> None:
        candidate = self.workflow + "\n# unreviewed but otherwise inert drift\n"
        with self.assertRaisesRegex(verify.VerificationError, "digest drift"):
            verify.verify_integration_workflow(self.manifest, candidate)

    def test_boolean_pull_request_number_is_refused(self) -> None:
        self.assertFalse(
            verify.workflow_context_allowed(
                "axiomlayer/ripgrep",
                "master",
                "pull_request",
                "refs/pull/True/merge",
                base_ref="master",
                event_number=True,
            )
        )

    def test_daily_canary_and_exact_trigger_set_are_required(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("cron: '17 6 * * *'", "cron: '17 6 * * 1'"),
            "daily canary drifted",
        )
        self.assert_workflow_rejected(
            self.workflow.replace(
                "  workflow_dispatch:\n", "  workflow_dispatch:\n  workflow_run:\n"
            ),
            "trigger set",
        )

    def test_floating_and_self_hosted_runners_are_refused(self) -> None:
        mutations = (
            (
                self.workflow.replace(
                    "runs-on: ubuntu-24.04", "runs-on: ubuntu-latest", 1
                ),
                "exact hosted job runners",
            ),
            (
                self.workflow.replace(
                    "runner: ubuntu-24.04-arm", "runner: self-hosted", 1
                ),
                "self-hosted runner|exact hosted runner matrix",
            ),
            (
                self.workflow.replace(
                    "runs-on: ubuntu-24.04",
                    "runs-on:\n      group: private-fleet\n      labels: ubuntu-24.04",
                    1,
                ),
                "real fleet access|runner group|exact hosted job runners",
            ),
        )
        for candidate, message in mutations:
            with self.subTest(message=message):
                self.assert_workflow_rejected(candidate, message)

    def test_matrix_build_modes_cannot_green_skip_source_builds(self) -> None:
        candidate = self.workflow.replace(
            "build_mode: nix-native", "build_mode: skip-source-build", 1
        )
        rehashed = copy.deepcopy(self.manifest)
        rehashed["workflowFirewall"]["activeWorkflow"]["sha256"] = hashlib.sha256(
            candidate.encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(
            verify.VerificationError, "build mode.*matrix drifted"
        ):
            verify.verify_integration_workflow(rehashed, candidate)

    def test_source_build_step_conditions_are_exact(self) -> None:
        candidate = self.workflow.replace(
            "if: matrix.build_mode == 'nix-native'",
            "if: matrix.build_mode == 'never-build'",
            1,
        )
        rehashed = copy.deepcopy(self.manifest)
        rehashed["workflowFirewall"]["activeWorkflow"]["sha256"] = hashlib.sha256(
            candidate.encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(verify.VerificationError, "step conditions"):
            verify.verify_integration_workflow(rehashed, candidate)

    def test_dirty_checkout_is_refused(self) -> None:
        for replacement in ("", "          clean: false\n"):
            with self.subTest(replacement=replacement.strip() or "missing"):
                self.assert_workflow_rejected(
                    self.workflow.replace("          clean: true\n", replacement, 1),
                    "clean: true",
                )

    def test_checkout_is_bound_to_the_event_sha(self) -> None:
        for replacement in ("", "          ref: refs/heads/master\n"):
            with self.subTest(replacement=replacement.strip() or "missing"):
                self.assert_workflow_rejected(
                    self.workflow.replace(
                        "          ref: ${{ github.sha }}\n", replacement, 1
                    ),
                    "ref: \\$\\{\\{\\ github\\.sha\\ \\}\\}",
                )

    def test_checkout_credentials_are_refused(self) -> None:
        mutations = (
            (
                self.workflow.replace("persist-credentials: false", "", 1),
                "persist-credentials: false",
            ),
            (
                self.workflow.replace(
                    "persist-credentials: false", "persist-credentials: true", 1
                ),
                "persist-credentials: false",
            ),
            (
                self.workflow.replace(
                    "          persist-credentials: false",
                    "          persist-credentials: false\n"
                    "          token: ${{ github.token }}",
                    1,
                ),
                "secret reference",
            ),
        )
        for candidate, message in mutations:
            with self.subTest(message=message):
                self.assert_workflow_rejected(candidate, message)

    def test_floating_action_fails_closed(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@v4",
                1,
            ),
            "action inventory drifted",
        )

    def test_forbidden_active_capabilities_fail_closed(self) -> None:
        additions = {
            "secret reference": "\nenv:\n  TOKEN: ${{ secrets['REAL_TOKEN'] }}\n",
            "write authority": "\npermissions:\n  contents: write\n",
            "publishing": "\nrun: cargo publish\n",
            "release": "\nrun: gh release create v999\n",
            "upstream sync": "\nrun: git pull --ff-only upstream master\n",
            "environment": "\nenvironment: production\n",
            "fleet": "\nrun: ssh ocelot.internal\n",
            "container image": "\ncontainer: ubuntu:latest\n",
        }
        expected = {
            "secret reference": "secret reference",
            "write authority": "write authority",
            "publishing": "publishing or release operation",
            "release": "publishing or release operation",
            "upstream sync": "upstream synchronization",
            "environment": "deployment environment",
            "fleet": "real fleet access",
            "container image": "job or service container",
        }
        for label, addition in additions.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(verify.VerificationError, expected[label]):
                    verify.verify_integration_boundaries(self.workflow + addition)

    def test_unreviewed_full_sha_action_fails_closed(self) -> None:
        with self.assertRaisesRegex(verify.VerificationError, "unreviewed"):
            verify.verify_action_references(
                "steps:\n  - uses: unreviewed/example@" + "0" * 40 + "\n",
                Path("unreviewed.yml"),
                self.manifest["workflowActions"],
            )

    def test_allowlisted_floating_action_fails_closed(self) -> None:
        with self.assertRaisesRegex(verify.VerificationError, "full commit"):
            verify.verify_action_references(
                "steps:\n  - uses: actions/checkout@v4\n",
                Path("floating.yml"),
                self.manifest["workflowActions"],
            )

    def test_nix_bootstrap_digest_tampering_fails_closed(self) -> None:
        source = HERE / "install-nix-ci.sh"
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "install-nix-ci.sh"
            candidate.write_bytes(source.read_bytes() + b"\n# drift\n")
            with self.assertRaisesRegex(verify.VerificationError, "digest mismatch"):
                verify.verify_nix_bootstrap(self.manifest, candidate)

    def test_nix_bootstrap_requires_empty_environment(self) -> None:
        text = (HERE / "install-nix-ci.sh").read_text(encoding="utf-8")
        with self.assertRaisesRegex(verify.VerificationError, "lost required boundary"):
            verify.verify_nix_bootstrap_text(
                self.manifest["nix"], text.replace("env -i", "env")
            )

    def test_nix_bootstrap_refuses_ambient_path_or_temp_root(self) -> None:
        text = (HERE / "install-nix-ci.sh").read_text(encoding="utf-8")
        for candidate in (
            text.replace("PATH=$SYSTEM_PATH", 'PATH="$PATH"'),
            text.replace(
                "mktemp -d /tmp/axiom-nix-ci.XXXXXXXX",
                'mktemp -d "${TMPDIR:-/tmp}/axiom-nix-ci.XXXXXXXX"',
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(verify.VerificationError):
                    verify.verify_nix_bootstrap_text(self.manifest["nix"], candidate)

    def test_nix_bootstrap_refuses_live_credentials(self) -> None:
        text = (HERE / "install-nix-ci.sh").read_text(encoding="utf-8")
        with self.assertRaisesRegex(verify.VerificationError, "credential surface"):
            verify.verify_nix_bootstrap_text(
                self.manifest["nix"], text + "\n# GITHUB_TOKEN\n"
            )

    def test_nix_expression_repeats_reviewed_pins(self) -> None:
        expression = (HERE / "default.nix").read_text(encoding="utf-8")
        self.assertIn(self.manifest["promotion"]["version"], expression)
        self.assertIn(self.manifest["nix"]["nixpkgs"]["commit"], expression)
        self.assertIn(self.manifest["nix"]["nixpkgs"]["narHash"], expression)
        verify.verify_nix_expression(self.manifest, HERE / "default.nix")

    def test_nix_expression_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "default.nix"
            candidate.write_bytes((HERE / "default.nix").read_bytes() + b"\n# drift\n")
            with self.assertRaisesRegex(verify.VerificationError, "digest mismatch"):
                verify.verify_nix_expression(self.manifest, candidate)

    def test_missing_native_surface_fails_closed(self) -> None:
        bad = copy.deepcopy(self.manifest)
        del bad["targets"]["windows-aarch64"]
        with self.assertRaises(verify.VerificationError):
            verify.validate_manifest(bad)

    def test_archive_digest_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.tar.gz"
            artifact.write_bytes(b"tampered archive")
            with self.assertRaises(verify.VerificationError):
                verify.assert_file_digest(artifact, "0" * 64, "archive")

    def test_extracted_binary_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "rg"
            binary.write_bytes(b"tampered binary")
            with self.assertRaises(verify.VerificationError):
                verify.assert_file_digest(binary, "f" * 64, "binary")

    def test_download_is_streamed_under_the_reviewed_byte_bound(self) -> None:
        class Response(io.BytesIO):
            def __init__(self, payload: bytes, content_length: str | None = None):
                super().__init__(payload)
                self.headers = {}
                if content_length is not None:
                    self.headers["Content-Length"] = content_length

        cases = (
            (b"exact", 5, "5", False),
            (b"too-large", 5, None, True),
            (b"tiny", 5, None, True),
            (b"exact", 5, "6", True),
        )
        for payload, expected, content_length, rejected in cases:
            with self.subTest(
                payload=payload,
                expected=expected,
                content_length=content_length,
            ), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "artifact"
                response = Response(payload, content_length)
                with mock.patch.object(
                    verify.urllib.request, "urlopen", return_value=response
                ):
                    if rejected:
                        with self.assertRaises(verify.VerificationError):
                            verify.download(
                                "https://example.invalid/artifact",
                                destination,
                                expected,
                            )
                        self.assertFalse(destination.exists())
                        self.assertFalse(
                            destination.with_suffix(".partial").exists()
                        )
                    else:
                        verify.download(
                            "https://example.invalid/artifact",
                            destination,
                            expected,
                        )
                        self.assertEqual(destination.read_bytes(), payload)

    def test_archive_path_traversal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "escape.tar.gz"
            payload = b"escape"
            with tarfile.open(archive, "w:gz") as tarred:
                member = tarfile.TarInfo("../escape")
                member.size = len(payload)
                tarred.addfile(member, io.BytesIO(payload))
            with self.assertRaises(verify.VerificationError):
                verify.extract_archive(archive, Path(temporary) / "extract")

    def test_duplicate_and_backslash_archive_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.tar.gz"
            with tarfile.open(duplicate, "w:gz") as tarred:
                for payload in (b"first", b"second"):
                    member = tarfile.TarInfo("root/rg")
                    member.size = len(payload)
                    tarred.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(verify.VerificationError, "duplicate"):
                verify.extract_archive(duplicate, root / "duplicate-extract")

            backslash = root / "backslash.tar.gz"
            with tarfile.open(backslash, "w:gz") as tarred:
                payload = b"escape"
                member = tarfile.TarInfo("root\\rg")
                member.size = len(payload)
                tarred.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(verify.VerificationError, "backslash"):
                verify.extract_archive(backslash, root / "backslash-extract")

    def test_manifest_serialization_is_stable_json(self) -> None:
        encoded = json.dumps(self.manifest, sort_keys=True)
        self.assertEqual(self.manifest, json.loads(encoded))

    def test_duplicate_manifest_keys_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "manifest.json"
            candidate.write_text('{"schema":"first","schema":"second"}\n')
            with self.assertRaisesRegex(verify.VerificationError, "duplicate JSON key"):
                verify.load_manifest(candidate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
