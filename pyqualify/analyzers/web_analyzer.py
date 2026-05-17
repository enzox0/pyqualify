"""Web analyzer for security, SEO, accessibility, and performance analysis."""





from __future__ import annotations





import asyncio


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


                form_findings = await self._check_forms(soup)


                findings.extend(form_findings)





                seo_findings = await self._check_seo(soup)


                findings.extend(seo_findings)





                a11y_findings = await self._check_accessibility(soup)


                findings.extend(a11y_findings)





                perf_findings = await self._check_performance(soup, load_time)


                findings.extend(perf_findings)





                link_findings = await self._check_links(soup, target)


                findings.extend(link_findings)





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





