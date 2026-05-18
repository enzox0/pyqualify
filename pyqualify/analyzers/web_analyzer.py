"""Web analyzer for security, SEO, accessibility, and performance analysis."""





from __future__ import annotations





import asyncio
import re

import time


from datetime import datetime, timezone


from urllib.parse import urljoin, urlparse





import httpx


from bs4 import BeautifulSoup





from pyqualify.ai.protocol import AIEngineProtocol


from pyqualify.logging.logger import PyqualifyLogger


from pyqualify.models import (


    AnalysisConfig,


    AnalysisContext,


    AnalysisMetadata,


    AnalysisMode,


    AnalysisResult,


    RawFinding,


    RiskLevel,


)


from pyqualify.scoring.engine import ScoringEngine
from pyqualify.tool_registry import ToolSelector


from pyqualify.utils import resolve_location, truncate_evidence








# Security headers to check with their severities


_SECURITY_HEADERS: dict[str, str] = {


    "Content-Security-Policy": "high",


    "Strict-Transport-Security": "high",


    "X-Frame-Options": "medium",


    "Referrer-Policy": "medium",


    "Permissions-Policy": "medium",


}





# CSRF token field name patterns


_CSRF_PATTERNS: list[str] = [


    "csrf_token",


    "_token",


    "authenticity_token",


    "csrfmiddlewaretoken",


]





# Sensitive input field indicators


_SENSITIVE_INPUT_PATTERNS: list[str] = [


    "password",


    "cc-number",


    "cc-csc",


    "cc-exp",


    "credit-card",


    "card-number",


    "cvv",


    "cvc",


    "ssn",


    "social-security",


]





# Known brand domains for homoglyph detection


_KNOWN_BRANDS: list[str] = [


    "google", "facebook", "amazon", "apple", "microsoft",


    "paypal", "netflix", "twitter", "instagram", "linkedin",


    "github", "dropbox", "spotify", "slack", "zoom",


]





# Common homoglyph substitutions


_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["а", "ɑ", "α"],  # Cyrillic a, Latin alpha, Greek alpha
    "e": ["е", "ё", "ε"],  # Cyrillic e, Cyrillic yo, Greek epsilon
    "o": ["о", "ο", "0"],        # Cyrillic o, Greek omicron, zero
    "i": ["і", "ι", "1", "l"],  # Cyrillic i, Greek iota, one, lowercase L
    "c": ["с", "ϲ"],              # Cyrillic c, Greek lunate sigma
    "p": ["р", "ρ"],              # Cyrillic p, Greek rho
    "s": ["ѕ", "ꜱ"],              # Cyrillic s, small capital S
    "x": ["х", "χ"],              # Cyrillic x, Greek chi
}








class WebAnalyzer:


    """Analyzes web pages for security, SEO, accessibility, and performance.





    Performs comprehensive analysis including:


    - Security header verification


    - Form CSRF token detection


    - SEO element completeness


    - Accessibility compliance checks


    - Performance signal analysis


    - Broken and suspicious link detection


    """





    def __init__(


        self,


        ai_engine: AIEngineProtocol,


        http_client: httpx.AsyncClient,


        logger: PyqualifyLogger,


    ) -> None:


        self._ai_engine = ai_engine


        self._http_client = http_client


        self._logger = logger


        self._scoring_engine = ScoringEngine()





    async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult:


        """Run full web analysis on the given URL.





        Orchestrates all checks, passes findings to AI engine, and computes


        score/grade/risk level.





        Args:


            target: The URL to analyze.


            config: Configuration for the analysis run.





        Returns:


            A complete AnalysisResult with all findings processed.


        """


        self._logger.info("web_analyzer", f"Starting analysis of {target}")


        findings: list[RawFinding] = []





        # Phase 1: Fetch headers with 10s timeout


        response: httpx.Response | None = None


        try:


            response = await asyncio.wait_for(


                self._http_client.get(target, follow_redirects=True),


                timeout=10.0,


            )


        except (asyncio.TimeoutError, httpx.RequestError) as e:


            self._logger.error(


                "web_analyzer",


                f"Failed to retrieve headers from {target}: {e}",


            )


            findings.append(RawFinding(


                check="url-unreachable",


                category="connectivity",


                location=target,


                evidence=f"Failed to connect within 10s: {type(e).__name__}",


            ))





        if response is not None and response.status_code >= 400:


            self._logger.warning(


                "web_analyzer",


                f"Non-2xx status code {response.status_code} for {target}",


            )


            findings.append(RawFinding(


                check="non-2xx-response",


                category="connectivity",


                location=target,


                evidence=f"HTTP status code: {response.status_code}",


            ))





        # Phase 2: Check security headers if we got a response


        if response is not None and response.status_code < 400:


            if ToolSelector.from_config("web", config).is_enabled("security-headers"):
                header_findings = await self._check_security_headers(response)


                findings.extend(header_findings)





        # Phase 3: Fetch full page with 30s timeout for HTML analysis


        html_content: str | None = None


        load_time: float = 0.0


        if response is not None and response.status_code < 400:


            try:


                start_time = time.monotonic()


                full_response = await asyncio.wait_for(


                    self._http_client.get(target, follow_redirects=True),


                    timeout=config.timeout,


                )


                load_time = time.monotonic() - start_time


                html_content = full_response.text


            except asyncio.TimeoutError:


                self._logger.warning(


                    "web_analyzer",


                    f"Full page load timed out after {config.timeout}s for {target}",


                )


                findings.append(RawFinding(


                    check="page-load-timeout",


                    category="performance",


                    location=target,


                    evidence=f"Page failed to load within {config.timeout} seconds",


                ))


            except httpx.RequestError as e:


                self._logger.error(


                    "web_analyzer", f"Request error during full page load: {e}"


                )





        # Phase 4: Parse HTML and run content checks


        if html_content:


            try:


                soup = BeautifulSoup(html_content, "lxml")


            except Exception as e:


                self._logger.error(


                    "web_analyzer", f"HTML parsing error: {e}"


                )


                soup = None
            if soup:
                # Build tool selector from config
                tool_selector = ToolSelector.from_config("web", config)
                if tool_selector.only or tool_selector.exclude:
                    self._logger.info(
                        "web_analyzer",
                        f"Enabled tools: {tool_selector.get_enabled_tools()}",
                    )

                if tool_selector.is_enabled("forms"):
                    form_findings = await self._check_forms(soup)
                    findings.extend(form_findings)





                if tool_selector.is_enabled("seo"):
                    seo_findings = await self._check_seo(soup)


                    findings.extend(seo_findings)





                if tool_selector.is_enabled("accessibility"):
                    a11y_findings = await self._check_accessibility(soup)


                    findings.extend(a11y_findings)





                if tool_selector.is_enabled("performance"):
                    perf_findings = await self._check_performance(soup, load_time)


                    findings.extend(perf_findings)





                if tool_selector.is_enabled("links"):
                    link_findings = await self._check_links(soup, target)


                    findings.extend(link_findings)





                # Vulnerability checks (Tasks 2, 3, 4, 5)


                if tool_selector.is_enabled("captcha"):
                    captcha_findings = await self._check_captcha(soup)


                    findings.extend(captcha_findings)





                if tool_selector.is_enabled("smuggling-headers"):
                    smuggling_findings = await self._check_smuggling_headers(response)


                    findings.extend(smuggling_findings)





                if tool_selector.is_enabled("case-sensitivity"):
                    case_findings = await self._check_case_sensitivity(target)


                    findings.extend(case_findings)





                if tool_selector.is_enabled("json-hijacking"):
                    json_hijack_findings = await self._check_json_hijacking(soup)


                    findings.extend(json_hijack_findings)


                if tool_selector.is_enabled("open-redirect"):
                    redirect_findings = await self._check_open_redirect(soup, target)
                    findings.extend(redirect_findings)


                if tool_selector.is_enabled("dom-xss"):
                    dom_xss_findings = await self._check_dom_xss(soup)
                    findings.extend(dom_xss_findings)


        # Phase 4b: Header-based checks that need the response object
        if response is not None and response.status_code < 400:
            tool_selector_hdr = ToolSelector.from_config("web", config)
            if tool_selector_hdr.is_enabled("server-version-disclosure"):
                version_findings = await self._check_server_version_disclosure(response)
                findings.extend(version_findings)





        # Phase 5: Process findings through AI engine


        self._logger.info(


            "web_analyzer",


            f"Collected {len(findings)} raw findings, sending to AI engine",


        )


        context = AnalysisContext(


            mode=AnalysisMode.WEB,


            target=target,


        )


        issues = await self._ai_engine.process_findings(findings, context)





        # Phase 5.5: Post-process evidence truncation (Requirement 21.4)


        for issue in issues:


            issue.evidence = truncate_evidence(issue.evidence)





        # Phase 6: Calculate score, grade, and risk level


        score = self._scoring_engine.calculate_score(issues)


        grade = self._scoring_engine.derive_grade(score)


        risk_level = self._scoring_engine.derive_risk_level(issues)





        metadata = AnalysisMetadata(


            timestamp=datetime.now(timezone.utc).isoformat(),


            target=target,


            mode=AnalysisMode.WEB,


        )





        issue_count = len(issues)


        summary = (


            f"Web analysis of {target} found {issue_count} issue(s). "


            f"Score: {score}/100, Grade: {grade}, Risk: {risk_level}."


        )[:500]





        self._logger.info("web_analyzer", f"Analysis complete: {summary}")





        return AnalysisResult(


            score=score,


            grade=grade,


            risk_level=RiskLevel(risk_level),


            issues=issues,


            summary=summary,


            metadata=metadata,


        )





    async def _check_security_headers(


        self, response: httpx.Response


    ) -> list[RawFinding]:


        """Check for missing or misconfigured security headers.





        Checks: Content-Security-Policy, Strict-Transport-Security,


        X-Frame-Options, Referrer-Policy, Permissions-Policy.





        Args:


            response: The HTTP response to check headers on.





        Returns:


            List of findings for missing or misconfigured headers.


        """


        findings: list[RawFinding] = []


        url = str(response.url)





        for header_name, severity in _SECURITY_HEADERS.items():


            header_value = response.headers.get(header_name)





            if header_value is None:


                findings.append(RawFinding(


                    check=f"missing-{header_name.lower()}-header",


                    category="security",


                    location=url,


                    evidence=f"Header '{header_name}' is not present in the response",


                    context={"severity_hint": severity},


                ))


            else:


                # Check for insecure configurations


                misconfig = self._check_header_misconfiguration(


                    header_name, header_value


                )


                if misconfig:


                    findings.append(RawFinding(


                        check=f"misconfigured-{header_name.lower()}-header",


                        category="security",


                        location=url,


                        evidence=f"{header_name}: {header_value} --- {misconfig}",


                        context={"severity_hint": "medium"},


                    ))





        return findings





    def _check_header_misconfiguration(


        self, header_name: str, header_value: str


    ) -> str | None:


        """Check if a security header has an insecure configuration.





        Args:


            header_name: The header name.


            header_value: The header value.





        Returns:


            A description of the misconfiguration, or None if secure.


        """


        lower_value = header_value.lower()





        if header_name == "Strict-Transport-Security":


            # Check max-age < 31536000 (1 year)


            if "max-age=" in lower_value:


                try:


                    max_age_str = lower_value.split("max-age=")[1].split(";")[0].strip()


                    max_age = int(max_age_str)


                    if max_age < 31536000:


                        return (


                            f"max-age={max_age} is below recommended minimum "


                            f"of 31536000 (1 year)"


                        )


                except (ValueError, IndexError):


                    pass





        elif header_name == "Content-Security-Policy":


            issues = []


            if "unsafe-inline" in lower_value:


                issues.append("contains 'unsafe-inline'")


            if "unsafe-eval" in lower_value:


                issues.append("contains 'unsafe-eval'")


            if issues:


                return "; ".join(issues)





        elif header_name == "X-Frame-Options":


            if lower_value.strip() == "allowall":


                return "set to ALLOWALL which provides no protection"





        elif header_name == "Permissions-Policy":


            if "=*" in header_value:


                return "grants permissions to all origins"





        return None





    async def _check_forms(self, html: BeautifulSoup) -> list[RawFinding]:


        """Check forms for missing CSRF tokens and sensitive autocomplete.





        Checks state-changing forms (POST/PUT/PATCH/DELETE) for CSRF tokens.


        Checks sensitive input fields for autocomplete settings.


        Skips GET forms for CSRF validation.





        Args:


            html: Parsed HTML document.





        Returns:


            List of findings for form security issues.


        """


        findings: list[RawFinding] = []


        forms = html.find_all("form")





        for form in forms:


            method = (form.get("method") or "get").upper()


            action = form.get("action") or ""





            # Skip GET forms for CSRF checks (Requirement 3.4)


            if method == "GET":


                continue





            # Check for CSRF token in state-changing forms


            if method in ("POST", "PUT", "PATCH", "DELETE"):


                has_csrf = self._form_has_csrf_token(form, html)


                if not has_csrf:


                    findings.append(RawFinding(


                        check="missing-csrf-token",


                        category="security",


                        location=resolve_location(action, fallback="[form action unresolved]"),


                        evidence=(


                            f"Form with method={method} and action='{action}' "


                            f"lacks a CSRF token"


                        ),


                        context={"severity_hint": "high"},


                    ))





            # Check sensitive input fields for autocomplete


            inputs = form.find_all("input")


            for inp in inputs:


                if self._is_sensitive_input(inp):


                    autocomplete = inp.get("autocomplete", "").lower()


                    if autocomplete != "off":


                        inp_name = inp.get("name") or inp.get("id") or "[unnamed]"


                        findings.append(RawFinding(


                            check="sensitive-autocomplete-enabled",


                            category="security",


                            location=resolve_location(action, fallback="[form action unresolved]"),


                            evidence=(


                                f"Sensitive input '{inp_name}' has autocomplete "


                                f"enabled (autocomplete='{autocomplete or 'on'}')"


                            ),


                            context={"severity_hint": "medium"},


                        ))





        return findings





    def _form_has_csrf_token(self, form: object, html: BeautifulSoup) -> bool:


        """Check if a form contains a CSRF token.





        Looks for hidden input fields with CSRF-related names, or a meta tag


        with a CSRF token value.





        Args:


            form: The form element to check.


            html: The full HTML document (for meta tag check).





        Returns:


            True if a CSRF token is found, False otherwise.


        """


        # Check hidden inputs in the form


        hidden_inputs = form.find_all("input", {"type": "hidden"})  # type: ignore[union-attr]


        for inp in hidden_inputs:


            name = (inp.get("name") or "").lower()


            if any(pattern in name for pattern in _CSRF_PATTERNS):


                return True





        # Check for CSRF meta tag in the document head


        meta_tags = html.find_all("meta")


        for meta in meta_tags:


            name = (meta.get("name") or "").lower()


            if any(pattern in name for pattern in _CSRF_PATTERNS):


                return True





        return False





    def _is_sensitive_input(self, inp: object) -> bool:


        """Determine if an input field is sensitive.





        Sensitive fields include password inputs and fields with names or


        autocomplete attributes indicating credit cards, security codes,


        or government identifiers.





        Args:


            inp: The input element to check.





        Returns:


            True if the input is sensitive, False otherwise.


        """


        input_type = (inp.get("type") or "").lower()  # type: ignore[union-attr]


        if input_type == "password":


            return True





        input_name = (inp.get("name") or "").lower()  # type: ignore[union-attr]


        autocomplete_attr = (inp.get("autocomplete") or "").lower()  # type: ignore[union-attr]





        combined = f"{input_name} {autocomplete_attr}"


        return any(pattern in combined for pattern in _SENSITIVE_INPUT_PATTERNS)





    async def _check_seo(self, html: BeautifulSoup) -> list[RawFinding]:


        """Check for missing SEO elements.





        Checks: title, meta description, canonical link, Open Graph tags,


        and robots meta tag.





        Args:


            html: Parsed HTML document.





        Returns:


            List of findings for missing SEO elements.


        """


        findings: list[RawFinding] = []





        # Check title tag


        title = html.find("title")


        if not title or not title.get_text(strip=True):


            findings.append(RawFinding(


                check="missing-title-tag",


                category="seo",


                location="<head>",


                evidence="Page is missing a <title> tag or title is empty",


                context={"severity_hint": "low"},


            ))





        # Check meta description


        meta_desc = html.find("meta", attrs={"name": "description"})


        if not meta_desc or not meta_desc.get("content", "").strip():


            findings.append(RawFinding(


                check="missing-meta-description",


                category="seo",


                location="<head>",


                evidence="Page is missing a meta description tag or content is empty",


                context={"severity_hint": "low"},


            ))





        # Check canonical link


        canonical = html.find("link", attrs={"rel": "canonical"})


        if not canonical:


            findings.append(RawFinding(


                check="missing-canonical-link",


                category="seo",


                location="<head>",


                evidence="Page is missing a canonical link element",


                context={"severity_hint": "low"},


            ))





        # Check Open Graph tags


        og_tags = ["og:title", "og:description", "og:image", "og:url"]


        for og_tag in og_tags:


            meta_og = html.find("meta", attrs={"property": og_tag})


            if not meta_og or not meta_og.get("content", "").strip():


                findings.append(RawFinding(


                    check=f"missing-{og_tag.replace(':', '-')}-tag",


                    category="seo",


                    location="<head>",


                    evidence=f"Page is missing Open Graph tag: {og_tag}",


                    context={"severity_hint": "info"},


                ))





        # Check robots meta tag


        robots_meta = html.find("meta", attrs={"name": "robots"})


        if not robots_meta:


            findings.append(RawFinding(


                check="missing-robots-meta",


                category="seo",


                location="<head>",


                evidence="Page is missing a robots meta tag",


                context={"severity_hint": "info"},


            ))





        return findings





    async def _check_accessibility(self, html: BeautifulSoup) -> list[RawFinding]:


        """Check accessibility compliance.





        Checks: alt attributes on images, heading hierarchy, lang attribute,


        ARIA roles on interactive elements, and form labels.





        Args:


            html: Parsed HTML document.





        Returns:


            List of findings for accessibility issues.


        """


        findings: list[RawFinding] = []





        # Check images without alt attributes


        images = html.find_all("img")


        for img in images:


            if not img.get("alt") and img.get("alt") != "":


                src = img.get("src") or "[no src]"


                findings.append(RawFinding(


                    check="missing-alt-attribute",


                    category="accessibility",


                    location=f"img[src='{src[:100]}']",


                    evidence=f"Image element lacks alt attribute: <img src='{src[:100]}'>",


                    context={"severity_hint": "medium"},


                ))





        # Check heading hierarchy


        headings = html.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])


        if headings:


            prev_level = 0


            for heading in headings:


                level = int(heading.name[1])


                if prev_level > 0 and level > prev_level + 1:


                    findings.append(RawFinding(


                        check="heading-hierarchy-skip",


                        category="accessibility",


                        location=f"<{heading.name}>",


                        evidence=(


                            f"Heading level skips from h{prev_level} to "


                            f"h{level}: '{heading.get_text(strip=True)[:50]}'"


                        ),


                        context={"severity_hint": "medium"},


                    ))


                prev_level = level





        # Check lang attribute on html element


        html_tag = html.find("html")


        if html_tag and not html_tag.get("lang"):


            findings.append(RawFinding(


                check="missing-lang-attribute",


                category="accessibility",


                location="<html>",


                evidence="The <html> element lacks a lang attribute",


                context={"severity_hint": "medium"},


            ))





        # Check ARIA roles on interactive elements


        interactive_elements = html.find_all(


            ["button", "a", "input", "select", "textarea"]


        )


        # Native elements that already convey their role don't need explicit ARIA


        native_role_elements = {"button", "a", "select", "textarea"}


        for elem in interactive_elements:


            tag_name = elem.name


            if tag_name in native_role_elements:


                continue


            # Inputs with type that conveys role are fine


            if tag_name == "input":


                input_type = (elem.get("type") or "text").lower()


                # These input types have implicit roles


                implicit_role_types = {


                    "button", "checkbox", "radio", "range", "submit",


                    "reset", "image", "search",


                }


                if input_type in implicit_role_types:


                    continue


            # Check for role attribute


            if not elem.get("role"):


                elem_id = elem.get("id") or elem.get("name") or tag_name


                findings.append(RawFinding(


                    check="missing-aria-role",


                    category="accessibility",


                    location=f"{tag_name}#{elem_id}",


                    evidence=(


                        f"Interactive element <{tag_name}> lacks an ARIA role "


                        f"attribute and does not use a native element that "


                        f"conveys the equivalent role"


                    ),


                    context={"severity_hint": "medium"},


                ))





        # Check form labels


        form_inputs = html.find_all("input")


        for inp in form_inputs:


            input_type = (inp.get("type") or "text").lower()


            # Skip hidden, submit, button, reset, image inputs


            if input_type in ("hidden", "submit", "button", "reset", "image"):


                continue


            input_id = inp.get("id")


            has_label = False


            if input_id:


                label = html.find("label", attrs={"for": input_id})


                if label:


                    has_label = True


            if not has_label and not inp.get("aria-label"):


                # Check if wrapped in a label


                parent_label = inp.find_parent("label")


                if not parent_label:


                    inp_name = inp.get("name") or inp.get("id") or "[unnamed]"


                    findings.append(RawFinding(


                        check="missing-form-label",


                        category="accessibility",


                        location=f"input[name='{inp_name}']",


                        evidence=(


                            f"Input element '{inp_name}' lacks an associated "


                            f"<label> element or aria-label attribute"


                        ),


                        context={"severity_hint": "medium"},


                    ))





        return findings





    async def _check_performance(


        self, html: BeautifulSoup, load_time: float


    ) -> list[RawFinding]:


        """Check performance signals.





        Checks: inline script sizes (>1KB), lazy loading for below-fold


        images, and DOMContentLoaded time (>3s).





        Args:


            html: Parsed HTML document.


            load_time: Measured page load time in seconds.





        Returns:


            List of findings for performance issues.


        """


        findings: list[RawFinding] = []





        # Check inline scripts exceeding 1KB


        scripts = html.find_all("script")


        for script in scripts:


            # Only check inline scripts (no src attribute)


            if script.get("src"):


                continue


            content = script.get_text()


            size_bytes = len(content.encode("utf-8"))


            if size_bytes > 1024:


                size_kb = size_bytes / 1024


                findings.append(RawFinding(


                    check="large-inline-script",


                    category="performance",


                    location="<script> (inline)",


                    evidence=(


                        f"Inline script is {size_kb:.1f}KB "


                        f"({size_bytes} bytes), exceeds 1KB threshold"


                    ),


                    context={"severity_hint": "low", "size_bytes": size_bytes},


                ))





        # Check images without lazy loading below the fold (>900px)


        # We approximate "below fold" by checking image position in document order


        # Images after the first 900px of content are considered below-fold


        images = html.find_all("img")


        # Heuristic: images beyond the 3rd image are likely below the fold


        # since we can't measure pixel position from HTML alone


        for idx, img in enumerate(images):


            if idx < 3:  # First few images are likely above the fold


                continue


            loading = (img.get("loading") or "").lower()


            if loading != "lazy":


                src = img.get("src") or "[no src]"


                findings.append(RawFinding(


                    check="missing-lazy-loading",


                    category="performance",


                    location=f"img[src='{src[:100]}']",


                    evidence=(


                        f"Image '{src[:80]}' is positioned below the fold "


                        f"but lacks loading='lazy' attribute"


                    ),


                    context={"severity_hint": "low"},


                ))





        # Check DOMContentLoaded time (using load_time as proxy)


        if load_time > 3.0:


            findings.append(RawFinding(


                check="slow-dom-content-loaded",


                category="performance",


                location="page",


                evidence=(


                    f"DOMContentLoaded time: {load_time * 1000:.0f}ms "


                    f"(exceeds 3000ms threshold)"


                ),


                context={"severity_hint": "medium", "load_time_ms": load_time * 1000},


            ))





        return findings





    async def _check_links(


        self, html: BeautifulSoup, base_url: str


    ) -> list[RawFinding]:


        """Verify links on the page.





        Checks up to 500 links with 5-second timeout per request.


        Detects broken links and suspicious domains (homoglyphs).





        Args:


            html: Parsed HTML document.


            base_url: The base URL for resolving relative links.





        Returns:


            List of findings for broken or suspicious links.


        """


        findings: list[RawFinding] = []


        anchors = html.find_all("a", href=True)





        # Collect unique URLs, limit to 500


        urls_to_check: list[str] = []


        seen: set[str] = set()





        for anchor in anchors:


            href = anchor.get("href", "").strip()


            if not href or href.startswith("#") or href.startswith("javascript:"):


                continue


            absolute_url = urljoin(base_url, href)


            if absolute_url not in seen:


                seen.add(absolute_url)


                urls_to_check.append(absolute_url)


            if len(urls_to_check) >= 500:


                break





        # Check for suspicious domains first (no network needed)


        for url in urls_to_check:


            suspicious = self._check_suspicious_domain(url)


            if suspicious:


                findings.append(RawFinding(


                    check="suspicious-link-domain",


                    category="security",


                    location=url,


                    evidence=f"Suspicious domain detected: {suspicious}",


                    context={"severity_hint": "high"},


                ))





        # Verify links with HTTP requests (5s timeout per request)


        async def check_single_link(url: str) -> RawFinding | None:


            try:


                resp = await asyncio.wait_for(


                    self._http_client.head(url, follow_redirects=True),


                    timeout=5.0,


                )


                if 400 <= resp.status_code < 500:


                    return RawFinding(


                        check="broken-link-4xx",


                        category="links",


                        location=url,


                        evidence=f"Link returned HTTP {resp.status_code}",


                        context={"severity_hint": "medium", "status": resp.status_code},


                    )


                elif resp.status_code >= 500:


                    return RawFinding(


                        check="broken-link-5xx",


                        category="links",


                        location=url,


                        evidence=f"Link returned HTTP {resp.status_code}",


                        context={"severity_hint": "high", "status": resp.status_code},


                    )


            except asyncio.TimeoutError:


                return RawFinding(


                    check="link-timeout",


                    category="links",


                    location=url,


                    evidence=f"Link verification timed out after 5 seconds",


                    context={"severity_hint": "low"},


                )


            except httpx.RequestError as e:


                return RawFinding(


                    check="link-connection-error",


                    category="links",


                    location=url,


                    evidence=f"Link verification failed: {type(e).__name__}",


                    context={"severity_hint": "low"},


                )


            return None





        # Run link checks concurrently in batches to avoid overwhelming


        batch_size = 20


        for i in range(0, len(urls_to_check), batch_size):


            batch = urls_to_check[i : i + batch_size]


            results = await asyncio.gather(


                *[check_single_link(url) for url in batch],


                return_exceptions=True,


            )


            for result in results:


                if isinstance(result, RawFinding):


                    findings.append(result)





        return findings





    def _check_suspicious_domain(self, url: str) -> str | None:


        """Check if a URL's domain uses homoglyph substitution.





        Compares the domain against known brand names, checking for


        character substitutions that could indicate phishing.





        Args:


            url: The URL to check.





        Returns:


            A description of the suspicious pattern, or None if clean.


        """


        try:


            parsed = urlparse(url)


            domain = parsed.hostname or ""


        except Exception:


            return None





        if not domain:


            return None





        # Remove TLD for comparison


        domain_parts = domain.split(".")


        if len(domain_parts) < 2:


            return None





        # Check the main domain name (second-level domain)


        main_domain = domain_parts[-2].lower()





        for brand in _KNOWN_BRANDS:


            if main_domain == brand:


                continue  # Exact match is fine





            # Check if domain looks like a brand with homoglyph substitutions


            if len(main_domain) == len(brand):


                substitutions = []


                for i, (dc, bc) in enumerate(zip(main_domain, brand)):


                    if dc != bc:


                        # Check if dc is a known homoglyph of bc


                        if bc in _HOMOGLYPHS and dc in _HOMOGLYPHS[bc]:


                            substitutions.append(


                                f"'{dc}' substituted for '{bc}' at position {i}"


                            )


                if substitutions:


                    return (


                        f"Domain '{domain}' resembles '{brand}' with "


                        f"homoglyph substitution: {'; '.join(substitutions)}"


                    )





        return None






    # --- Task 2: Guessable CAPTCHA ---

    async def _check_captcha(self, html: BeautifulSoup) -> list[RawFinding]:
        """Detect forms with missing or weak CAPTCHA on sensitive pages."""
        findings: list[RawFinding] = []

        # Sensitive form action keywords
        sensitive_keywords = ["login", "register", "signup", "contact", "reset", "forgot"]

        # Known CAPTCHA provider indicators
        captcha_providers = [
            "www.google.com/recaptcha",
            "hcaptcha.com",
            "challenges.cloudflare.com",
            "recaptcha",
            "h-captcha",
            "cf-turnstile",
        ]

        forms = html.find_all("form")
        page_text = str(html).lower()

        # Check if page has any known CAPTCHA provider
        has_captcha_provider = any(provider in page_text for provider in captcha_providers)

        for form in forms:
            action = (form.get("action") or "").lower()
            form_id = (form.get("id") or "").lower()
            form_class = " ".join(form.get("class", [])).lower() if form.get("class") else ""
            combined = f"{action} {form_id} {form_class}"

            # Check if this is a sensitive form
            is_sensitive = any(kw in combined for kw in sensitive_keywords)
            if not is_sensitive:
                continue

            # Check for CAPTCHA in this form
            form_html = str(form).lower()
            form_has_captcha = (
                has_captcha_provider
                or any(provider in form_html for provider in captcha_providers)
                or form.find("div", class_=lambda c: c and "captcha" in c.lower() if c else False)
                or form.find("input", attrs={"name": lambda n: n and "captcha" in n.lower() if n else False})
            )

            if not form_has_captcha:
                findings.append(RawFinding(
                    check="missing-captcha",
                    category="security",
                    location=action or "[form]",
                    evidence=(
                        f"Sensitive form (action=\'{action}\') lacks CAPTCHA protection. "
                        f"Login/registration forms should have CAPTCHA to prevent brute force."
                    ),
                    context={"severity_hint": "medium", "vulnerability_type": "captcha"},
                ))
            else:
                # Check for weak CAPTCHA patterns (simple math)
                if form.find("input", attrs={"name": lambda n: n and "captcha" in n.lower() if n else False}):
                    # Look for adjacent math question
                    form_text = form.get_text().lower()
                    if any(op in form_text for op in ["what is", "solve:", "calculate"]):
                        findings.append(RawFinding(
                            check="weak-captcha",
                            category="security",
                            location=action or "[form]",
                            evidence=(
                                f"Form uses a simple math-based CAPTCHA which is easily "
                                f"bypassable by automated tools."
                            ),
                            context={"severity_hint": "medium", "vulnerability_type": "captcha"},
                        ))

        return findings

    # --- Task 3: HTTP Request Smuggling Headers ---

    async def _check_smuggling_headers(self, response) -> list[RawFinding]:
        """Check response headers for Transfer-Encoding and Content-Length co-existence."""
        findings: list[RawFinding] = []

        if response is None:
            return findings

        headers = response.headers
        has_te = "transfer-encoding" in headers
        has_cl = "content-length" in headers

        if has_te and has_cl:
            findings.append(RawFinding(
                check="smuggling-header-coexistence",
                category="security",
                location=str(response.url),
                evidence=(
                    f"Response contains both Transfer-Encoding and Content-Length headers. "
                    f"This can indicate susceptibility to HTTP request smuggling. "
                    f"TE: {headers.get('transfer-encoding')}, CL: {headers.get('content-length')}"
                ),
                context={"severity_hint": "high", "vulnerability_type": "http-request-smuggling"},
            ))

        return findings

    # --- Task 4: Case Sensitivity ---

    async def _check_case_sensitivity(self, target_url: str) -> list[RawFinding]:
        """Check if URL path casing changes produce different access results."""
        findings: list[RawFinding] = []

        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(target_url)
        path = parsed.path

        if not path or path == "/":
            return findings

        # Try uppercase version of the path
        upper_path = path.upper()
        if upper_path == path:
            return findings

        upper_url = urlunparse(parsed._replace(path=upper_path))

        try:
            original_resp = await asyncio.wait_for(
                self._http_client.get(target_url, follow_redirects=True),
                timeout=5.0,
            )
            upper_resp = await asyncio.wait_for(
                self._http_client.get(upper_url, follow_redirects=True),
                timeout=5.0,
            )

            orig_status = original_resp.status_code
            upper_status = upper_resp.status_code

            # If a forbidden path becomes accessible with different casing
            if orig_status in (403, 404) and upper_status in range(200, 300):
                findings.append(RawFinding(
                    check="case-sensitive-access-bypass",
                    category="security",
                    location=target_url,
                    evidence=(
                        f"Case sensitivity bypass: original path returns {orig_status}, "
                        f"uppercase path returns {upper_status}. Access control may be bypassable."
                    ),
                    context={"severity_hint": "high", "vulnerability_type": "case-sensitivity"},
                ))
            elif upper_status in (403, 404) and orig_status in range(200, 300):
                # Reverse case - uppercase is blocked but original isn't (inconsistent)
                pass  # This is normal behavior

        except (asyncio.TimeoutError, httpx.RequestError):
            pass

        return findings

    # --- Open Redirect Detection ---

    async def _check_open_redirect(self, html: BeautifulSoup, target_url: str) -> list[RawFinding]:
        """Detect open redirect vectors in HTML forms and links.

        Checks for redirect/return_url/next parameters in forms and links
        that could be abused for phishing via redirection.
        """
        findings: list[RawFinding] = []

        # Redirect parameter names commonly abused
        redirect_params = [
            "redirect", "redirect_uri", "redirect_url", "return", "return_url",
            "returnto", "next", "url", "goto", "target", "destination", "redir",
            "continue", "forward",
        ]

        # Check forms for redirect parameters
        forms = html.find_all("form")
        for form in forms:
            action = form.get("action") or ""
            for param in redirect_params:
                if param in action.lower():
                    findings.append(RawFinding(
                        check="open-redirect-form-action",
                        category="security",
                        location=action[:200],
                        evidence=(
                            f"Form action contains redirect parameter '{param}': "
                            f"action='{action[:150]}'"
                        ),
                        context={"severity_hint": "medium", "vulnerability_type": "open-redirect", "param": param},
                    ))
                    break

            # Check hidden inputs for redirect values
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            for inp in hidden_inputs:
                name = (inp.get("name") or "").lower()
                value = inp.get("value") or ""
                if any(p == name for p in redirect_params):
                    # Flag if value looks like an external URL
                    if value.startswith("http") or value.startswith("//"):
                        findings.append(RawFinding(
                            check="open-redirect-hidden-input",
                            category="security",
                            location=action[:200] or "[form]",
                            evidence=(
                                f"Hidden input '{name}' contains external URL value: '{value[:100]}'. "
                                f"Could be abused for open redirect."
                            ),
                            context={"severity_hint": "high", "vulnerability_type": "open-redirect", "param": name},
                        ))

        # Check anchor links for redirect parameters pointing to external domains
        from urllib.parse import urlparse, parse_qs
        base_domain = urlparse(target_url).netloc

        anchors = html.find_all("a", href=True)
        for anchor in anchors:
            href = anchor.get("href", "")
            if not href or href.startswith("#"):
                continue
            try:
                parsed = urlparse(href)
                qs = parse_qs(parsed.query)
                for param in redirect_params:
                    if param in qs:
                        values = qs[param]
                        for val in values:
                            val_parsed = urlparse(val)
                            if val_parsed.netloc and val_parsed.netloc != base_domain:
                                findings.append(RawFinding(
                                    check="open-redirect-link",
                                    category="security",
                                    location=href[:200],
                                    evidence=(
                                        f"Link contains redirect parameter '{param}' pointing to "
                                        f"external domain '{val_parsed.netloc}': {href[:150]}"
                                    ),
                                    context={"severity_hint": "high", "vulnerability_type": "open-redirect", "param": param},
                                ))
            except Exception:
                continue

        return findings

    # --- Server Version / Technology Disclosure ---

    async def _check_server_version_disclosure(self, response: httpx.Response) -> list[RawFinding]:
        """Detect server version and technology information in response headers.

        Checks Server, X-Powered-By, X-AspNet-Version, X-Generator and similar
        headers that leak version information useful to attackers.
        """
        findings: list[RawFinding] = []
        url = str(response.url)

        disclosure_headers = {
            "Server": "server-version-disclosure",
            "X-Powered-By": "technology-disclosure",
            "X-AspNet-Version": "aspnet-version-disclosure",
            "X-AspNetMvc-Version": "aspnet-mvc-version-disclosure",
            "X-Generator": "generator-disclosure",
            "X-Drupal-Cache": "cms-disclosure",
            "X-Joomla-Version": "cms-version-disclosure",
            "X-WordPress-Version": "cms-version-disclosure",
        }

        # Version pattern: digits with dots (e.g. Apache/2.4.51, PHP/8.1.0)
        version_pattern = r'\d+\.\d+'

        for header_name, check_name in disclosure_headers.items():
            value = response.headers.get(header_name)
            if not value:
                continue

            # Flag if value contains a version number or known tech name
            has_version = bool(re.search(version_pattern, value))
            tech_keywords = [
                "apache", "nginx", "iis", "php", "asp", "express", "django",
                "rails", "tomcat", "jetty", "gunicorn", "uvicorn", "werkzeug",
                "python", "ruby", "java", "node", "microsoft",
            ]
            has_tech = any(kw in value.lower() for kw in tech_keywords)

            if has_version or has_tech:
                findings.append(RawFinding(
                    check=check_name,
                    category="security",
                    location=url,
                    evidence=(
                        f"Header '{header_name}' discloses version/technology: '{value}'. "
                        f"Attackers can use this to target known vulnerabilities."
                    ),
                    context={"severity_hint": "low", "header": header_name, "value": value},
                ))

        return findings

    # --- DOM-based / Self-XSS Detection ---

    async def _check_dom_xss(self, html: BeautifulSoup) -> list[RawFinding]:
        """Detect DOM-based XSS sinks that read from URL fragments or query strings.

        Looks for patterns like document.URL, location.hash, location.search
        being passed to innerHTML, document.write, or eval without sanitization.
        """
        findings: list[RawFinding] = []

        # DOM sources (user-controlled input)
        dom_sources = [
            "location.hash", "location.search", "location.href",
            "document.url", "document.referrer", "window.name",
        ]

        # DOM sinks (dangerous output functions)
        dom_sinks = [
            "innerhtml", "outerhtml", "document.write", "document.writeln",
            "eval(", "settimeout(", "setinterval(", "execscript(",
            ".html(", "insertadjacenthtml",
        ]

        scripts = html.find_all("script")
        for script in scripts:
            if script.get("src"):
                continue  # Skip external scripts
            content = script.get_text()
            if not content:
                continue

            content_lower = content.lower()

            # Check if script reads from a DOM source
            has_source = any(src in content_lower for src in dom_sources)
            if not has_source:
                continue

            # Check if it also writes to a dangerous sink
            for sink in dom_sinks:
                if sink in content_lower:
                    # Check for sanitization patterns
                    sanitization_patterns = [
                        "dompurify", "sanitize", "escapehtml", "htmlencode",
                        "encodeuri", "encodeuricomponent", "textcontent",
                    ]
                    has_sanitization = any(s in content_lower for s in sanitization_patterns)

                    if not has_sanitization:
                        # Find the source used
                        source_used = next(
                            (src for src in dom_sources if src in content_lower), "unknown"
                        )
                        findings.append(RawFinding(
                            check="dom-based-xss",
                            category="security",
                            location="<script> (inline)",
                            evidence=(
                                f"Inline script reads from DOM source '{source_used}' "
                                f"and writes to sink '{sink}' without apparent sanitization. "
                                f"Potential DOM-based XSS."
                            ),
                            context={
                                "severity_hint": "high",
                                "vulnerability_type": "dom-xss",
                                "source": source_used,
                                "sink": sink,
                            },
                        ))
                        break  # One finding per script block

        return findings

    # --- Task 5: JSON Hijacking ---

    async def _check_json_hijacking(self, html: BeautifulSoup) -> list[RawFinding]:
        """Detect JSON hijacking vectors in HTML (script inclusions, constructor overrides)."""
        findings: list[RawFinding] = []

        scripts = html.find_all("script")

        for script in scripts:
            src = script.get("src", "")

            # Check for script tags loading JSON endpoints
            if src and (".json" in src.lower() or "/api/" in src.lower()):
                findings.append(RawFinding(
                    check="json-hijacking-script-inclusion",
                    category="security",
                    location=src,
                    evidence=(
                        f"Script tag loads JSON endpoint as JavaScript: src=\'{src[:100]}\'. "
                        f"This may allow cross-origin data theft via JSON hijacking."
                    ),
                    context={"severity_hint": "high", "vulnerability_type": "json-hijacking"},
                ))

            # Check inline scripts for Array/Object constructor overrides
            content = script.get_text()
            if content:
                override_patterns = [
                    "Array = function",
                    "Array=function",
                    "Object = function",
                    "Object=function",
                    "Array.prototype",
                    "__defineSetter__",
                ]
                for pattern in override_patterns:
                    if pattern in content:
                        findings.append(RawFinding(
                            check="json-array-constructor-override",
                            category="security",
                            location="<script> (inline)",
                            evidence=(
                                f"Inline script overrides {pattern.split('=')[0].split('.')[0].strip()} "
                                f"constructor/prototype. This is a classic JSON hijacking vector."
                            ),
                            context={"severity_hint": "critical", "vulnerability_type": "json-hijacking"},
                        ))
                        break

        return findings
