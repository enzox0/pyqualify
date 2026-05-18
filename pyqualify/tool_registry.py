"""Tool registry defining all available analysis tools per category.

Each analyzer (code, web, api) has a set of named tools that can be
individually enabled or disabled. By default, all tools are enabled.

Usage:
    from pyqualify.tool_registry import TOOL_REGISTRY, ToolSelector

    # Get all tools for a category
    tools = TOOL_REGISTRY["code"]

    # Create a selector that enables only specific tools
    selector = ToolSelector(category="api", only=["http-dos", "injection"])
    if selector.is_enabled("injection"):
        ...
"""

from dataclasses import dataclass, field
from typing import Any


# Tool definitions: category -> {tool_name: description}
TOOL_REGISTRY: dict[str, dict[str, str]] = {
    "code": {
        "security": "Detect injection vulnerabilities, hardcoded secrets, insecure patterns",
        "bug-risks": "Detect null dereferences, uncaught exceptions, race conditions",
        "quality": "Detect dead code, duplicated logic, high complexity, magic numbers",
        "test-gaps": "Detect missing tests, weak assertions, untested branches",
        "dependencies": "Detect typosquatting, deprecated packages, wildcard imports",
        "audit-log": "Detect log injection, log suppression, audit log deletion",
        "case-sensitivity": "Detect missing case normalization in auth/routing comparisons",
    },
    "web": {
        "security-headers": "Check for missing or misconfigured security headers",
        "forms": "Check forms for CSRF tokens and sensitive autocomplete",
        "seo": "Check for missing SEO elements (title, meta, OG tags)",
        "accessibility": "Check accessibility compliance (alt, headings, ARIA, labels)",
        "performance": "Check performance signals (inline scripts, lazy loading, load time)",
        "links": "Verify links for broken URLs and suspicious domains",
        "captcha": "Detect missing or weak CAPTCHA on sensitive forms",
        "smuggling-headers": "Check for Transfer-Encoding/Content-Length co-existence",
        "case-sensitivity": "Check if URL path casing changes bypass access controls",
        "json-hijacking": "Detect JSON hijacking vectors in HTML scripts",
    },
    "api": {
        "authentication": "Test authentication enforcement (no creds, expired/malformed tokens)",
        "response-integrity": "Test for information leakage and status code mismatches",
        "injection": "Test SQL, NoSQL, and command injection via payloads",
        "rate-limiting": "Test rate limiting by sending burst requests",
        "schema-conformance": "Validate response schema consistency across requests",
        "audit-log-manipulation": "Test for log injection via headers/params",
        "captcha-bypass": "Test if auth endpoints work without CAPTCHA",
        "http-request-smuggling": "Test for CL.TE / TE.CL request smuggling",
        "case-sensitivity": "Test for case-sensitive route/auth bypass",
        "json-hijacking": "Test for unprotected top-level JSON arrays",
    },
}


def get_all_tool_names(category: str) -> list[str]:
    """Get all tool names for a given category."""
    return list(TOOL_REGISTRY.get(category, {}).keys())


def get_tool_description(category: str, tool_name: str) -> str:
    """Get the description of a specific tool."""
    return TOOL_REGISTRY.get(category, {}).get(tool_name, "")


def list_tools_formatted(category: str | None = None) -> str:
    """Return a formatted string listing all tools, optionally filtered by category."""
    lines: list[str] = []
    categories = [category] if category else list(TOOL_REGISTRY.keys())

    for cat in categories:
        tools = TOOL_REGISTRY.get(cat, {})
        if not tools:
            continue
        lines.append(f"\n  {cat.upper()} tools:")
        for name, desc in tools.items():
            lines.append(f"    {name:<25} {desc}")

    return "\n".join(lines)


@dataclass
class ToolSelector:
    """Determines which tools are enabled for an analysis run.

    Supports three modes:
    1. All tools enabled (default) - when no filtering is specified
    2. Only specific tools - when `only` list is provided
    3. Exclude specific tools - when `exclude` list is provided

    If both `only` and `exclude` are provided, `only` takes precedence.

    Args:
        category: The analysis category (code, web, api).
        only: If set, ONLY these tools will run. All others are disabled.
        exclude: If set, these tools will be skipped. All others run.
    """

    category: str
    only: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)

    def is_enabled(self, tool_name: str) -> bool:
        """Check if a specific tool is enabled.

        Args:
            tool_name: The name of the tool to check.

        Returns:
            True if the tool should run, False if it should be skipped.
        """
        if self.only:
            return tool_name in self.only
        if self.exclude:
            return tool_name not in self.exclude
        return True

    def get_enabled_tools(self) -> list[str]:
        """Get the list of all enabled tool names for this category."""
        all_tools = get_all_tool_names(self.category)
        return [t for t in all_tools if self.is_enabled(t)]

    def get_disabled_tools(self) -> list[str]:
        """Get the list of all disabled tool names for this category."""
        all_tools = get_all_tool_names(self.category)
        return [t for t in all_tools if not self.is_enabled(t)]

    @classmethod
    def from_config(cls, category: str, config: Any) -> "ToolSelector":
        """Create a ToolSelector from an AnalysisConfig.

        Reads the `enabled_tools` and `disabled_tools` fields from config.

        Args:
            category: The analysis category.
            config: An AnalysisConfig instance.

        Returns:
            A configured ToolSelector.
        """
        only = getattr(config, "enabled_tools", None) or []
        exclude = getattr(config, "disabled_tools", None) or []
        return cls(category=category, only=only, exclude=exclude)
