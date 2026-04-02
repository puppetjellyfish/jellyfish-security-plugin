from __future__ import annotations

import json
import unittest
from pathlib import Path


class NativePluginPackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]

    def test_native_plugin_manifests_exist(self) -> None:
        package_json = self.repo_root / "package.json"
        plugin_manifest = self.repo_root / "openclaw.plugin.json"

        self.assertTrue(package_json.exists(), "package.json is required for a native OpenClaw plugin")
        self.assertTrue(
            plugin_manifest.exists(),
            "openclaw.plugin.json is required for a native OpenClaw plugin",
        )

    def test_package_metadata_declares_openclaw_compatibility(self) -> None:
        package_json = json.loads((self.repo_root / "package.json").read_text(encoding="utf-8"))
        openclaw = package_json.get("openclaw", {})
        compat = openclaw.get("compat", {})
        build = openclaw.get("build", {})

        self.assertTrue(openclaw.get("extensions"), "openclaw.extensions must be declared")
        self.assertTrue(compat.get("pluginApi"), "openclaw.compat.pluginApi must be declared")
        self.assertTrue(build.get("openclawVersion"), "openclaw.build.openclawVersion must be declared")

    def test_plugin_manifest_declares_config_schema(self) -> None:
        manifest = json.loads((self.repo_root / "openclaw.plugin.json").read_text(encoding="utf-8"))

        self.assertTrue(manifest.get("id"), "plugin manifest must declare an id")
        self.assertTrue(manifest.get("configSchema"), "plugin manifest must declare a config schema")


if __name__ == "__main__":
    unittest.main()
