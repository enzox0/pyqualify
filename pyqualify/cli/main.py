"""QAAI CLI main command group.

Provides the top-level CLI entry point with web, code, and api analysis
commands, plus a config subgroup for managing configuration.

When invoked with no subcommand, an interactive menu guides the user
through mode selection and target input. On first run, a setup wizard
collects the required provider and API key before proceeding.
"""

import asyncio
import json
import os
import sys

import click
import httpx

from pyqualify import __version__
from pyqualify.ai.engine import AIEngine, _PROVIDER_DEFAULTS
from pyqualify.analyzers.api_analyzer import APIAnalyzer
from pyqualify.analyzers.code_analyzer import CodeAnalyzer
from pyqualify.analyzers.web_analyzer import WebAnalyzer
from pyqualify.cli.progress import ProgressIndicator
from pyqualify.cli.validators import validate_path, validate_url
from pyqualify.config.manager import ConfigManager
from pyqualify.container import Container
from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import AIConfig, AnalysisConfig, AnalysisMode, LogConfig
from pyqualify.reporting.cli_formatter import CLIFormatter
from pyqualify.reporting.html_generator import HTMLDashboardGenerator
from pyqualify.reporting.pdf_generator import PDFReportGenerator, resolve_pdf_path
from pyqualify.tool_registry import TOOL_REGISTRY, list_tools_formatted

# -- Provider catalogue --------------------------------------------------------

_PROVIDERS = {
    "1": ("openai",    "OpenAI",    "GPT-4o, GPT-4-turbo, GPT-3.5-turbo, ..."),
    "2": ("anthropic", "Anthropic", "Claude 3.5 Sonnet, Claude 3 Opus, ..."),
    "3": ("google",    "Google",    "Gemini 2.0 Flash, Gemini 1.5 Pro, ..."),
    "4": ("groq",      "Groq",      "Llama 3.3 70B, Mixtral 8x7B, ..."),
}

# -- Analysis mode catalogue ---------------------------------------------------

_MODES = {
    "1": ("Web",  "Analyze a website for security, SEO, accessibility & performance"),
    "2": ("Code", "Analyze source code for vulnerabilities, quality & test gaps"),
    "3": ("API",  "Analyze REST API endpoints for security & integrity"),
}

# -- Banner --------------------------------------------------------------------

def _print_banner(config_manager: "ConfigManager | None" = None) -> None:
    # Clear the terminal before drawing the banner
    os.system("cls" if os.name == "nt" else "clear")

    banner = r"""
██████╗ ██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██╗     ██╗███████╗██╗   ██╗
██╔══██╗╚██╗ ██╔╝██╔═══██╗██║   ██║██╔══██╗██║     ██║██╔════╝╚██╗ ██╔╝
██████╔╝ ╚████╔╝ ██║   ██║██║   ██║███████║██║     ██║█████╗   ╚████╔╝ 
██╔═══╝   ╚██╔╝  ██║▄▄ ██║██║   ██║██╔══██║██║     ██║██╔══╝    ╚██╔╝  
██║        ██║   ╚██████╔╝╚██████╔╝██║  ██║███████╗██║██║        ██║   
╚═╝        ╚═╝    ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚═╝        ╚═╝  
"""
    click.echo(click.style(banner, fg="cyan", bold=True))
    click.echo(click.style("  AI-Powered QA & Security Analysis", fg="bright_blue"))
    click.echo(
        click.style("  by ", fg="bright_black") +
        click.style("enzox0", fg="magenta")
    )
    click.echo(click.style("  " + "─" * 70, fg="bright_black"))

    # -- Resolve real system data ----------------------------------------------
    version_str = f"v{__version__}"

    if config_manager is not None:
        provider = config_manager.get("provider", "openai")
        defaults = _PROVIDER_DEFAULTS.get(provider, _PROVIDER_DEFAULTS["openai"])
        is_configured = config_manager.is_configured()
        engine_str = (config_manager.get("model") or defaults["model"]) if is_configured else "not configured"
    else:
        engine_str = "not configured"
        is_configured = False

    status_str = "● ready" if is_configured else "○ setup needed"
    status_color = "green" if is_configured else "yellow"

    cols = [
        ("version", version_str,  "green"),
        ("engine",  engine_str,   "cyan"),
        ("mode",    "interactive", "yellow"),
        ("status",  status_str,   status_color),
    ]
    row = "  ".join(
        click.style(f"{k:<9}", fg="bright_black") + click.style(v, fg=color)
        for k, v, color in cols
    )
    click.echo("  " + row + "\n")

# -- First-run setup wizard ----------------------------------------------------

def _run_setup(config_manager: ConfigManager) -> None:
    """Interactive setup wizard - collects provider, API key, and model."""
    click.echo(click.style("  Setup", fg="white", bold=True) +
               click.style("  configure your AI provider\n", fg="bright_black"))
    click.echo(click.style("  Choose a provider:\n", fg="bright_black"))

    for key, (slug, name, models) in _PROVIDERS.items():
        click.echo(
            f"  {click.style(key, fg='cyan', bold=True)}  "
            f"{click.style(name, bold=True):<12}  "
            f"{click.style(models, fg='bright_black')}"
        )
    click.echo()

    while True:
        choice = click.prompt(
            click.style("  Provider", bold=True),
            prompt_suffix=click.style(" [1/2/3/4] ", fg="bright_black"),
            default="1",
        ).strip()
        if choice in _PROVIDERS:
            provider_slug, provider_name, _ = _PROVIDERS[choice]
            break
        click.echo(click.style("  ○ Please enter 1, 2, 3, or 4.", fg="yellow"))

    defaults = _PROVIDER_DEFAULTS[provider_slug]
    default_model = defaults["model"]

    click.echo()
    api_key = click.prompt(
        click.style(f"  {provider_name} API key", bold=True),
        prompt_suffix="\n  > ",
        hide_input=True,
        default="",
        show_default=False,
    ).strip()
    if not api_key:
        click.echo(
            click.style("  ✖ API key cannot be empty. Setup cancelled.", fg="red")
        )
        sys.exit(1)

    click.echo()
    model = click.prompt(
        click.style("  Model", bold=True),
        prompt_suffix=click.style(f" (default: {default_model})", fg="bright_black") + "\n  > ",
        default=default_model,
        show_default=False,
    ).strip() or default_model

    # Persist
    config_manager.set("provider", provider_slug)
    config_manager.set("api_key", api_key)
    config_manager.set("model", model)

    click.echo()
    click.echo(
        "  " +
        click.style("✔ ", fg="green", bold=True) +
        click.style("Configuration saved.", fg="green", bold=True)
    )
    click.echo(
        "  " +
        click.style("provider   ", fg="bright_black") +
        click.style(provider_name, fg="cyan") +
        click.style("  model   ", fg="bright_black") +
        click.style(model + "\n", fg="cyan")
    )

def _ensure_configured(config_manager: ConfigManager) -> None:
    """Block execution if the tool has not been configured yet."""
    if not config_manager.is_configured():
        _print_banner(config_manager)
        click.echo(
            "  " +
            click.style("○ ", fg="yellow") +
            click.style("PyQualify is not configured yet.\n", fg="yellow")
        )
        click.echo(
            click.style("  Run the setup wizard to get started:\n", fg="bright_black")
        )
        click.echo(
            "  " +
            click.style("uv run pyqualify setup", fg="cyan", bold=True) +
            "\n"
        )
        sys.exit(1)

# -- Interactive analysis menu -------------------------------------------------

def _prompt_mode() -> str:
    """Prompt the user to select an analysis mode. Returns 'web', 'code', or 'api'."""
    click.echo(click.style("  Select analysis mode:\n", fg="white", bold=True))
    for key, (name, desc) in _MODES.items():
        click.echo(
            f"  {click.style(key, fg='cyan', bold=True)}  "
            f"{click.style(name, bold=True):<6}  "
            f"{click.style(desc, fg='bright_black')}"
        )
    click.echo()

    while True:
        choice = click.prompt(
            click.style("  Mode", bold=True),
            prompt_suffix=click.style(" [1/2/3] ", fg="bright_black"),
            default="1",
        ).strip()
        if choice in _MODES:
            return _MODES[choice][0].lower()
        click.echo(click.style("  ○ Please enter 1, 2, or 3.", fg="yellow"))


def _prompt_target(mode: str) -> str:
    """Prompt for the analysis target appropriate to the mode."""
    prompts = {
        "web":  ("  Target URL",              "https://example.com"),
        "code": ("  Path to file or directory", "./src"),
        "api":  ("  API base URL",             "https://api.example.com"),
    }
    label, placeholder = prompts[mode]
    click.echo()
    while True:
        target = click.prompt(
            click.style(label, bold=True),
            prompt_suffix=click.style(f" (e.g. {placeholder})", fg="bright_black") + "\n  > ",
            default="",
            show_default=False,
        ).strip()
        if not target:
            click.echo(click.style("  ○ Target cannot be empty.", fg="yellow"))
            continue
        try:
            if mode in ("web", "api"):
                return validate_url(target)
            else:
                return validate_path(target)
        except click.BadParameter as e:
            click.echo(click.style(f"  ○ {e.format_message()}", fg="yellow"))


def _prompt_output_options() -> tuple[bool, bool]:
    """Prompt for optional PDF save and JSON flag.

    Returns:
        (save_pdf, json_output)
    """
    click.echo()
    save_pdf = click.confirm(
        click.style("  Save PDF report to Documents/PyQualify/?", fg="white", bold=True),
        default=True,
    )
    return save_pdf, False


def _run_interactive() -> None:
    """Full interactive session: config check -> banner -> mode -> target -> options -> analysis."""
    config_manager = ConfigManager()
    _ensure_configured(config_manager)
    _print_banner(config_manager)

    try:
        mode = _prompt_mode()
        target = _prompt_target(mode)
        save_pdf, json_output = _prompt_output_options()

        click.echo()

        analysis_config = _resolve_analysis_config(config_manager, save_pdf, json_output)
        container = _build_container(config_manager)
        formatter = container.resolve(CLIFormatter)
        pdf_generator = container.resolve(PDFReportGenerator)

        mode_labels = {"web": "web page", "code": "source code", "api": "API endpoints"}
        with ProgressIndicator(f"Analyzing {mode_labels[mode]}"):
            if mode == "web":
                analyzer = container.resolve(WebAnalyzer)
            elif mode == "code":
                analyzer = container.resolve(CodeAnalyzer)
            else:
                analyzer = container.resolve(APIAnalyzer)
            result = asyncio.run(analyzer.analyze(target, analysis_config))

        formatter.generate_cli_output(result)

        if save_pdf:
            pdf_path = resolve_pdf_path(target)
            pdf_generator.generate_pdf_report(result, pdf_path)
            click.echo(
                "  " +
                click.style("✔ ", fg="green", bold=True) +
                click.style(f"PDF report saved to: {pdf_path}", fg="green"),
                err=True,
            )

    except KeyboardInterrupt:
        click.echo(
            "\n\n  " + click.style("○ Cancelled.", fg="yellow"),
            err=True,
        )
        sys.exit(130)
    except click.BadParameter as e:
        click.echo(
            "\n  " + click.style(f"✖ {e.format_message()}", fg="red"),
            err=True,
        )
        sys.exit(1)
    except Exception as e:
        click.echo(
            "\n  " + click.style(f"✖ {e}", fg="red"),
            err=True,
        )
        sys.exit(1)


def _build_container(config_manager: ConfigManager) -> Container:
    """Wire the DI container with all implementations.

    Args:
        config_manager: The resolved configuration manager.

    Returns:
        A fully wired Container instance.
    """
    container = Container()

    # Register ConfigManager as singleton
    container.register_singleton(ConfigManager, lambda: config_manager)

    # Register Logger as singleton
    def _create_logger() -> PyqualifyLogger:
        log_level = config_manager.get("log_level", "WARNING")
        log_file = config_manager.get("log_file")
        return PyqualifyLogger(LogConfig(level=log_level, log_file=log_file))

    container.register_singleton(PyqualifyLogger, _create_logger)

    # Register AI Engine as singleton
    def _create_ai_engine() -> AIEngine:
        api_key = config_manager.get("api_key", "")
        provider = config_manager.get("provider", "openai")
        base_url = config_manager.get("base_url", "")
        model = config_manager.get("model", "")
        timeout = int(config_manager.get("ai_timeout", "60"))
        max_retries = int(config_manager.get("max_retries", "3"))
        retry_delay = float(config_manager.get("retry_delay", "2.0"))
        ai_config = AIConfig(
            api_key=api_key,
            provider=provider,
            base_url=base_url,
            model=model,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
        )
        logger = container.resolve(PyqualifyLogger)
        return AIEngine(config=ai_config, logger=logger)

    container.register_singleton(AIEngine, _create_ai_engine)

    # Register CLIFormatter as singleton
    container.register_singleton(CLIFormatter, CLIFormatter)

    # Register PDFReportGenerator as singleton
    container.register_singleton(PDFReportGenerator, PDFReportGenerator)

    # Register WebAnalyzer as transient (needs fresh http_client per run)
    def _create_web_analyzer() -> WebAnalyzer:
        ai_engine = container.resolve(AIEngine)
        logger = container.resolve(PyqualifyLogger)
        timeout = int(config_manager.get("timeout", "30"))
        http_client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        return WebAnalyzer(ai_engine=ai_engine, http_client=http_client, logger=logger)

    container.register(WebAnalyzer, _create_web_analyzer)

    # Register CodeAnalyzer as transient
    def _create_code_analyzer() -> CodeAnalyzer:
        ai_engine = container.resolve(AIEngine)
        logger = container.resolve(PyqualifyLogger)
        return CodeAnalyzer(ai_engine=ai_engine, logger=logger)

    container.register(CodeAnalyzer, _create_code_analyzer)

    # Register APIAnalyzer as transient (needs fresh http_client per run)
    def _create_api_analyzer() -> APIAnalyzer:
        ai_engine = container.resolve(AIEngine)
        logger = container.resolve(PyqualifyLogger)
        timeout = int(config_manager.get("timeout", "30"))
        http_client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        return APIAnalyzer(ai_engine=ai_engine, http_client=http_client, logger=logger)

    container.register(APIAnalyzer, _create_api_analyzer)

    return container


def _resolve_analysis_config(
    config_manager: ConfigManager,
    pdf_output: bool,
    json_output: bool,
    enabled_tools: list[str] | None = None,
    disabled_tools: list[str] | None = None,
) -> AnalysisConfig:
    """Build an AnalysisConfig from config manager values and CLI options.

    Args:
        config_manager: The configuration manager.
        pdf_output: Whether to save a PDF report.
        json_output: Whether to output raw JSON.
        enabled_tools: If set, only these tools will run.
        disabled_tools: If set, these tools will be skipped.

    Returns:
        A resolved AnalysisConfig instance.
    """
    timeout = int(config_manager.get("timeout", "30"))
    max_links = int(config_manager.get("max_links", "500"))
    rate_limit_burst = int(config_manager.get("rate_limit_burst", "50"))
    rate_limit_window = int(config_manager.get("rate_limit_window", "10"))

    return AnalysisConfig(
        timeout=timeout,
        max_links=max_links,
        rate_limit_burst=rate_limit_burst,
        rate_limit_window=rate_limit_window,
        pdf_output=pdf_output,
        json_output=json_output,
        enabled_tools=enabled_tools or [],
        disabled_tools=disabled_tools or [],
    )


@click.group(invoke_without_command=True)
@click.version_option(package_name="pyqualify")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """PyQualify - AI-powered QA and Security Analysis Tool.

    Run without a subcommand to launch the interactive mode selector.
    """
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        _run_interactive()


@cli.command()
def setup() -> None:
    """Configure your AI provider and API key (run this first)."""
    config_manager = ConfigManager()
    _print_banner(config_manager)
    already = config_manager.is_configured()
    if already:
        provider = config_manager.get("provider", "openai")
        model = config_manager.get("model", "")
        provider_names = {"openai": "OpenAI", "anthropic": "Anthropic", "google": "Google"}
        click.echo(
            "  " +
            click.style("provider   ", fg="bright_black") +
            click.style(provider_names.get(provider, provider), fg="cyan") +
            click.style("  model   ", fg="bright_black") +
            click.style(model or "(default)", fg="cyan") +
            "\n"
        )
        if not click.confirm(
            click.style("  Reconfigure?", fg="white", bold=True), default=False
        ):
            click.echo(
                "  " + click.style("○ No changes made.", fg="bright_black")
            )
            return
        click.echo()
    try:
        _run_setup(config_manager)
    except KeyboardInterrupt:
        click.echo(
            "\n\n  " + click.style("○ Setup cancelled.", fg="yellow")
        )
        sys.exit(130)


@cli.command()
@click.argument("url")
@click.option("--pdf", "save_pdf", is_flag=True, default=False, help="Save PDF report to Documents/PyQualify/")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output raw JSON")
@click.option("--only", "only_tools", multiple=True, help="Run ONLY these tools (comma-separated or repeated)")
@click.option("--disable", "disable_tools", multiple=True, help="Disable specific tools (comma-separated or repeated)")
@click.pass_context
def web(ctx: click.Context, url: str, save_pdf: bool, json_output: bool, only_tools: tuple, disable_tools: tuple) -> None:
    """Analyze web page security, SEO, accessibility, and performance.

    Use --only to run specific tools only, or --disable to skip certain tools.
    Run 'pyqualify tools web' to see available tools.
    """
    try:
        url = validate_url(url)

        # Parse tool selection (support comma-separated values)
        enabled = [t.strip() for raw in only_tools for t in raw.split(",") if t.strip()]
        disabled = [t.strip() for raw in disable_tools for t in raw.split(",") if t.strip()]

        config_manager = ConfigManager()
        analysis_config = _resolve_analysis_config(config_manager, save_pdf, json_output, enabled, disabled)
        container = _build_container(config_manager)

        analyzer = container.resolve(WebAnalyzer)
        formatter = container.resolve(CLIFormatter)
        pdf_generator = container.resolve(PDFReportGenerator)

        with ProgressIndicator("Analyzing web page"):
            result = asyncio.run(analyzer.analyze(url, analysis_config))

        if json_output:
            click.echo(json.dumps(result.to_dict(), indent=2))
        else:
            formatter.generate_cli_output(result)

        if save_pdf:
            pdf_path = resolve_pdf_path(url)
            pdf_generator.generate_pdf_report(result, pdf_path)
            click.echo(
                "  " +
                click.style("✔ ", fg="green", bold=True) +
                click.style(f"PDF report saved to: {pdf_path}", fg="green"),
                err=True,
            )

    except click.BadParameter as e:
        click.echo(
            "  " + click.style(f"✖ {e.format_message()}", fg="red"),
            err=True,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(
            "\n  " + click.style("○ Analysis interrupted.", fg="yellow"),
            err=True,
        )
        sys.exit(130)
    except Exception as e:
        click.echo(
            "  " + click.style(f"✖ {e}", fg="red"),
            err=True,
        )
        sys.exit(1)


@cli.command()
@click.argument("path")
@click.option("--pdf", "save_pdf", is_flag=True, default=False, help="Save PDF report to Documents/PyQualify/")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output raw JSON")
@click.option("--only", "only_tools", multiple=True, help="Run ONLY these tools (comma-separated or repeated)")
@click.option("--disable", "disable_tools", multiple=True, help="Disable specific tools (comma-separated or repeated)")
@click.pass_context
def code(ctx: click.Context, path: str, save_pdf: bool, json_output: bool, only_tools: tuple, disable_tools: tuple) -> None:
    """Analyze source code for security, quality, and test gaps.

    Use --only to run specific tools only, or --disable to skip certain tools.
    Run 'pyqualify tools code' to see available tools.
    """
    try:
        path = validate_path(path)

        # Parse tool selection (support comma-separated values)
        enabled = [t.strip() for raw in only_tools for t in raw.split(",") if t.strip()]
        disabled = [t.strip() for raw in disable_tools for t in raw.split(",") if t.strip()]

        config_manager = ConfigManager()
        analysis_config = _resolve_analysis_config(config_manager, save_pdf, json_output, enabled, disabled)
        container = _build_container(config_manager)

        analyzer = container.resolve(CodeAnalyzer)
        formatter = container.resolve(CLIFormatter)
        pdf_generator = container.resolve(PDFReportGenerator)

        with ProgressIndicator("Analyzing source code"):
            result = asyncio.run(analyzer.analyze(path, analysis_config))

        if json_output:
            click.echo(json.dumps(result.to_dict(), indent=2))
        else:
            formatter.generate_cli_output(result)

        if save_pdf:
            pdf_path = resolve_pdf_path(path)
            pdf_generator.generate_pdf_report(result, pdf_path)
            click.echo(
                "  " +
                click.style("✔ ", fg="green", bold=True) +
                click.style(f"PDF report saved to: {pdf_path}", fg="green"),
                err=True,
            )

    except click.BadParameter as e:
        click.echo(
            "  " + click.style(f"✖ {e.format_message()}", fg="red"),
            err=True,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(
            "\n  " + click.style("○ Analysis interrupted.", fg="yellow"),
            err=True,
        )
        sys.exit(130)
    except Exception as e:
        click.echo(
            "  " + click.style(f"✖ {e}", fg="red"),
            err=True,
        )
        sys.exit(1)


@cli.command()
@click.argument("base_url")
@click.option("--pdf", "save_pdf", is_flag=True, default=False, help="Save PDF report to Documents/PyQualify/")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output raw JSON")
@click.option("--only", "only_tools", multiple=True, help="Run ONLY these tools (comma-separated or repeated)")
@click.option("--disable", "disable_tools", multiple=True, help="Disable specific tools (comma-separated or repeated)")
@click.pass_context
def api(ctx: click.Context, base_url: str, save_pdf: bool, json_output: bool, only_tools: tuple, disable_tools: tuple) -> None:
    """Analyze API endpoints for security and integrity.

    Use --only to run specific tools only, or --disable to skip certain tools.
    Run 'pyqualify tools api' to see available tools.
    """
    try:
        base_url = validate_url(base_url)

        # Parse tool selection (support comma-separated values)
        enabled = [t.strip() for raw in only_tools for t in raw.split(",") if t.strip()]
        disabled = [t.strip() for raw in disable_tools for t in raw.split(",") if t.strip()]

        config_manager = ConfigManager()
        analysis_config = _resolve_analysis_config(config_manager, save_pdf, json_output, enabled, disabled)
        container = _build_container(config_manager)

        analyzer = container.resolve(APIAnalyzer)
        formatter = container.resolve(CLIFormatter)
        pdf_generator = container.resolve(PDFReportGenerator)

        with ProgressIndicator("Analyzing API endpoints"):
            result = asyncio.run(analyzer.analyze(base_url, analysis_config))

        if json_output:
            click.echo(json.dumps(result.to_dict(), indent=2))
        else:
            formatter.generate_cli_output(result)

        if save_pdf:
            pdf_path = resolve_pdf_path(base_url)
            pdf_generator.generate_pdf_report(result, pdf_path)
            click.echo(
                "  " +
                click.style("✔ ", fg="green", bold=True) +
                click.style(f"PDF report saved to: {pdf_path}", fg="green"),
                err=True,
            )

    except click.BadParameter as e:
        click.echo(
            "  " + click.style(f"✖ {e.format_message()}", fg="red"),
            err=True,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(
            "\n  " + click.style("○ Analysis interrupted.", fg="yellow"),
            err=True,
        )
        sys.exit(130)
    except Exception as e:
        click.echo(
            "  " + click.style(f"✖ {e}", fg="red"),
            err=True,
        )
        sys.exit(1)



@cli.command("tools")
@click.argument("category", required=False, default=None)
def list_tools_cmd(category: str | None) -> None:
    """List available analysis tools by category.

    Shows all tools that can be enabled/disabled with --only and --disable.

    \b
    Categories: code, web, api
    \b
    Examples:
      pyqualify tools          # List all tools
      pyqualify tools code     # List code analysis tools
      pyqualify tools api      # List API analysis tools
    """
    if category and category not in TOOL_REGISTRY:
        click.echo(
            click.style(f"  \u2716 Unknown category '{category}'. ", fg="red") +
            click.style(f"Available: {', '.join(TOOL_REGISTRY.keys())}", fg="bright_black"),
            err=True,
        )
        sys.exit(1)

    click.echo(click.style("\n  PyQualify Available Tools", fg="white", bold=True))
    click.echo(click.style("  " + "\u2500" * 50, fg="bright_black"))

    categories = [category] if category else list(TOOL_REGISTRY.keys())
    for cat in categories:
        tools = TOOL_REGISTRY.get(cat, {})
        click.echo(click.style(f"\n  {cat.upper()}", fg="cyan", bold=True) +
                   click.style(f"  ({len(tools)} tools)", fg="bright_black"))
        for name, desc in tools.items():
            click.echo(
                f"    {click.style(name, fg='green', bold=True):<35}"
                f"{click.style(desc, fg='bright_black')}"
            )

    click.echo(click.style("\n  Usage:", fg="white", bold=True))
    click.echo(click.style("    pyqualify api <url> --only injection,rate-limiting", fg="bright_black"))
    click.echo(click.style("    pyqualify code <path> --disable test-gaps,quality", fg="bright_black"))
    click.echo(click.style("    pyqualify web <url> --only security-headers", fg="bright_black"))
    click.echo()


@cli.command("dashboard")
@click.argument("mode", required=False, type=click.Choice(["web", "code", "api"]))
@click.argument("target", required=False)
def dashboard(mode: str | None, target: str | None) -> None:
    """Launch the TUI dashboard for interactive analysis.

    Optionally provide a MODE (web, code, or api) and a TARGET (URL or path)
    to auto-start analysis on launch.

    \b
    Examples:
      pyqualify dashboard
      pyqualify dashboard web https://example.com
      pyqualify dashboard code ./src
      pyqualify dashboard api https://api.example.com
    """
    # Validate: if target is provided, mode must also be provided
    if target and not mode:
        click.echo(
            "  " + click.style(
                "✖ Target provided without a mode. Please specify a mode (web, code, or api).",
                fg="red",
            ),
            err=True,
        )
        sys.exit(1)

    # Validate target based on mode
    if mode and target:
        try:
            if mode in ("web", "api"):
                validate_url(target)
            elif mode == "code":
                validate_path(target)
        except click.BadParameter as e:
            click.echo(
                "  " + click.style(f"✖ {e.format_message()}", fg="red"),
                err=True,
            )
            sys.exit(1)

    # Create container and check configuration status
    container = Container()
    config_manager = ConfigManager()
    container.register_singleton(ConfigManager, lambda: config_manager)

    if not config_manager.is_configured():
        click.echo(
            "\n  " + click.style("⚠ PyQualify is not configured.", fg="yellow")
        )
        click.echo(
            "  Run " + click.style("pyqualify setup", fg="cyan", bold=True)
            + " to configure your provider and API key.\n"
        )
        sys.exit(1)

    # Build fully wired container and launch TUI
    container = _build_container(config_manager)

    # Convert mode string to AnalysisMode enum if provided
    analysis_mode: AnalysisMode | None = None
    if mode:
        analysis_mode = AnalysisMode(mode)

    from pyqualify.tui.app import DashboardApp

    app = DashboardApp(container=container, mode=analysis_mode, target=target)
    app.run()


@cli.group()
def config() -> None:
    """Manage PyQualify configuration."""
    pass


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a configuration value."""
    try:
        config_manager = ConfigManager()
        config_manager.set(key, value)
        display_value = (
            ConfigManager.mask_value(value)
            if ConfigManager.is_sensitive_key(key)
            else value
        )
        click.echo(
            "  " +
            click.style("✔ ", fg="green", bold=True) +
            click.style(f"{key}", fg="bright_black") +
            click.style(" = ", fg="bright_black") +
            click.style(display_value, fg="cyan")
        )
    except Exception as e:
        click.echo("  " + click.style(f"✖ {e}", fg="red"), err=True)
        sys.exit(1)


@config.command("edit")
def config_edit() -> None:
    """Open interactive configuration editor."""
    try:
        from pyqualify.config.editor import ConfigEditor

        config_manager = ConfigManager()
        editor = ConfigEditor(config_manager)
        editor.run()
    except Exception as e:
        click.echo("  " + click.style(f"✖ {e}", fg="red"), err=True)
        sys.exit(1)


@config.command("list")
def config_list() -> None:
    """List all configuration values."""
    try:
        config_manager = ConfigManager()
        entries = config_manager.list_all()
        if not entries:
            click.echo(
                "  " + click.style("○ No configuration values set.", fg="bright_black")
            )
            return
        click.echo(click.style("  " + "─" * 40, fg="bright_black"))
        for key, value in sorted(entries.items()):
            click.echo(
                "  " +
                click.style(f"{key:<18}", fg="bright_black") +
                click.style(value, fg="cyan")
            )
        click.echo(click.style("  " + "─" * 40, fg="bright_black"))
    except Exception as e:
        click.echo("  " + click.style(f"✖ {e}", fg="red"), err=True)
        sys.exit(1)


@config.command("delete")
@click.argument("key")
def config_delete(key: str) -> None:
    """Delete a configuration value."""
    try:
        config_manager = ConfigManager()
        deleted = config_manager.delete(key)
        if deleted:
            click.echo(
                "  " +
                click.style("✔ ", fg="green", bold=True) +
                click.style(f"Deleted '{key}'.", fg="bright_black")
            )
        else:
            click.echo(
                "  " + click.style(f"○ Key '{key}' not found.", fg="yellow"),
                err=True,
            )
            sys.exit(1)
    except Exception as e:
        click.echo("  " + click.style(f"✖ {e}", fg="red"), err=True)
        sys.exit(1)
