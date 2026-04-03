#!/usr/bin/env python3
"""
Plugin System Architecture for ZEVS Scanner
Allows custom vulnerability modules to be loaded dynamically
"""

import importlib
import inspect
import os
from typing import List, Dict, Any, Callable, Optional
from abc import ABC, abstractmethod


class VulnerabilityPlugin(ABC):
    """Base class for all vulnerability plugins"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass

    @property
    @abstractmethod
    def severity(self) -> str:
        """Default severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"""
        pass

    @property
    def enabled(self) -> bool:
        """Whether plugin is enabled by default"""
        return True

    @property
    def requires_auth(self) -> bool:
        """Whether plugin requires authentication"""
        return False

    @abstractmethod
    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute vulnerability scan

        Args:
            target: Target URL
            **kwargs: Additional parameters (headers, cookies, etc.)

        Returns:
            List of findings, each dict with:
                - type: Vulnerability type
                - severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
                - url: Vulnerable URL
                - description: Finding description
                - evidence: Proof of vulnerability
                - payload: Attack payload used
                - remediation: Fix recommendation
        """
        pass


class PluginManager:
    """Manages loading and execution of vulnerability plugins"""

    def __init__(self, plugin_dir: str = "plugins"):
        """
        Initialize plugin manager

        Args:
            plugin_dir: Directory containing plugin files
        """
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, VulnerabilityPlugin] = {}
        self.load_plugins()

    def load_plugins(self):
        """Load all plugins from plugin directory"""
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            return

        # Find all .py files in plugin directory
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                module_name = filename[:-3]
                self._load_plugin_module(module_name)

    def _load_plugin_module(self, module_name: str):
        """Load a single plugin module"""
        try:
            # Import module
            spec = importlib.util.spec_from_file_location(
                module_name, os.path.join(self.plugin_dir, f"{module_name}.py")
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find plugin classes
            for name, obj in inspect.getmembers(module):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, VulnerabilityPlugin)
                    and obj != VulnerabilityPlugin
                ):
                    # Instantiate plugin
                    plugin = obj()
                    self.plugins[plugin.name] = plugin
                    print(f"[+] Loaded plugin: {plugin.name}")

        except Exception as e:
            print(f"[-] Failed to load plugin {module_name}: {str(e)}")

    def get_plugin(self, name: str) -> Optional[VulnerabilityPlugin]:
        """Get plugin by name"""
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        """List all loaded plugins"""
        return [
            {
                "name": plugin.name,
                "description": plugin.description,
                "severity": plugin.severity,
                "enabled": plugin.enabled,
                "requires_auth": plugin.requires_auth,
            }
            for plugin in self.plugins.values()
        ]

    def run_plugin(self, name: str, target: str, **kwargs) -> List[Dict]:
        """
        Run a specific plugin

        Args:
            name: Plugin name
            target: Target URL
            **kwargs: Additional parameters

        Returns:
            List of findings
        """
        plugin = self.get_plugin(name)
        if not plugin:
            raise ValueError(f"Plugin '{name}' not found")

        if not plugin.enabled:
            return []

        return plugin.scan(target, **kwargs)

    def run_all_plugins(self, target: str, **kwargs) -> Dict[str, List[Dict]]:
        """
        Run all enabled plugins

        Args:
            target: Target URL
            **kwargs: Additional parameters

        Returns:
            Dict mapping plugin name to findings
        """
        results = {}

        for name, plugin in self.plugins.items():
            if plugin.enabled:
                try:
                    findings = plugin.scan(target, **kwargs)
                    if findings:
                        results[name] = findings
                except Exception as e:
                    print(f"[-] Error running plugin {name}: {str(e)}")

        return results


# Example plugin implementation
class ExampleXSSPlugin(VulnerabilityPlugin):
    """Example XSS detection plugin"""

    @property
    def name(self) -> str:
        return "Custom XSS Scanner"

    @property
    def description(self) -> str:
        return "Custom XSS detection with advanced payloads"

    @property
    def severity(self) -> str:
        return "HIGH"

    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        findings = []

        # Example: Test XSS payloads
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]

        # In real implementation, you would:
        # 1. Send HTTP requests with payloads
        # 2. Check if payload is reflected
        # 3. Return findings

        # Example finding
        findings.append(
            {
                "type": "XSS",
                "severity": "HIGH",
                "url": f"{target}/search?q=test",
                "description": "Reflected XSS vulnerability found",
                "evidence": "Payload <script>alert(1)</script> reflected in response",
                "payload": "<script>alert(1)</script>",
                "remediation": "Implement proper output encoding and CSP headers",
            }
        )

        return findings


# Test
if __name__ == "__main__":
    print("ZEVS Plugin System Test\n")

    # Create plugin manager
    manager = PluginManager("plugins")

    # List plugins
    print("=== Loaded Plugins ===")
    plugins = manager.list_plugins()
    for plugin in plugins:
        print(f"- {plugin['name']}: {plugin['description']}")
    print()

    # Run example plugin
    print("=== Running Example Plugin ===")
    try:
        findings = manager.run_plugin("Custom XSS Scanner", "https://example.com")
        print(f"Found {len(findings)} vulnerabilities")
        for finding in findings:
            print(f"  [{finding['severity']}] {finding['type']} at {finding['url']}")
    except Exception as e:
        print(f"Error: {e}")

    print("\n=== Plugin System Ready ===")
    print("To create a custom plugin:")
    print("1. Create a .py file in the 'plugins' directory")
    print("2. Inherit from VulnerabilityPlugin")
    print("3. Implement required methods: name, description, severity, scan()")
    print("4. Plugin will be auto-loaded on next scan")
