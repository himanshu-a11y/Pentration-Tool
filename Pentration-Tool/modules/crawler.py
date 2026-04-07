# ...existing code...
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import time
import os
from collections import defaultdict
import re
import logging
from typing import Tuple, List, Dict, Set


class WebsiteAnalyzer:
    def __init__(self, session: requests.Session):
        self.session = session  # Use the shared session
        # Ensure headers updated in a safe way
        self.session.headers.update({"User-Agent": "Penetration-Tester/1.0 (Crawler)"})
        self.visited: Set[str] = set()
        self.results: List[Dict] = []
        self.metadata: Dict = {
            "title": None,
            "description": None,
            "keywords": None,
            "favicon": None,
            "technologies": set(),
            "social_media": set(),
            "emails": set(),
            "phone_numbers": set(),
        }
        self.stats = defaultdict(int)
        self.content_types = defaultdict(set)
        self.found_files = defaultdict(set)

    def extract_metadata(self, soup: BeautifulSoup, url: str) -> None:
        if soup.title and soup.title.string:
            self.metadata["title"] = soup.title.string.strip()
        for meta in soup.find_all("meta"):
            name = meta.get("name", "").lower()
            content = meta.get("content", "")
            if name == "description":
                self.metadata["description"] = content
            elif name == "keywords":
                self.metadata["keywords"] = content
        favicon = soup.find("link", rel="icon") or soup.find("link", rel="shortcut icon")
        if favicon and favicon.get("href"):
            self.metadata["favicon"] = urljoin(url, favicon["href"])
        self.detect_technologies(soup)

    def detect_technologies(self, soup: BeautifulSoup) -> None:
        scripts = soup.find_all("script", src=True)
        for script in scripts:
            src = script["src"].lower()
            if "react" in src:
                self.metadata["technologies"].add("React")
            elif "vue" in src:
                self.metadata["technologies"].add("Vue.js")
            elif "angular" in src:
                self.metadata["technologies"].add("Angular")
            elif "jquery" in src:
                self.metadata["technologies"].add("jQuery")
        links = soup.find_all("link", rel="stylesheet")
        for link in links:
            href = link.get("href", "").lower()
            if "bootstrap" in href:
                self.metadata["technologies"].add("Bootstrap")
            elif "tailwind" in href:
                self.metadata["technologies"].add("Tailwind CSS")

    def extract_contact_info(self, soup: BeautifulSoup, text: str) -> None:
        # Emails
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        self.metadata["emails"].update(re.findall(email_pattern, text))
        # Phones (simple heuristic)
        phone_pattern = r"\+?\d[\d\-\s().]{6,}\d"
        self.metadata["phone_numbers"].update(re.findall(phone_pattern, text))
        # Social links
        social_patterns = {
            "facebook.com": "Facebook",
            "twitter.com": "Twitter",
            "linkedin.com": "LinkedIn",
            "instagram.com": "Instagram",
            "youtube.com": "YouTube",
        }
        for a in soup.find_all("a", href=True):
            href = a["href"].lower()
            for pattern, platform in social_patterns.items():
                if pattern in href:
                    self.metadata["social_media"].add(f"{platform}: {href}")

    def analyze_content(self, soup: BeautifulSoup, url: str) -> None:
        if soup.find("article") or soup.find(class_=re.compile(r"blog|post|article")):
            self.content_types["blog"].add(url)
        elif soup.find("form", class_=re.compile(r"contact|enquiry")):
            self.content_types["contact"].add(url)
        elif soup.find(class_=re.compile(r"product|item|price")):
            self.content_types["product"].add(url)
        elif soup.find(class_=re.compile(r"about|team|company")):
            self.content_types["about"].add(url)
        self.stats["images"] += len(soup.find_all("img"))
        self.stats["links"] += len(soup.find_all("a"))
        self.stats["forms"] += len(soup.find_all("form"))
        self.stats["scripts"] += len(soup.find_all("script"))
        self.stats["styles"] += len(soup.find_all("link", rel="stylesheet"))

    def crawl(self, url: str, base: str, depth: int, max_depth: int) -> Tuple[List[Dict], Dict]:
        """Crawl the website and collect information. Returns (results, metadata)."""
        # Basic guards
        if depth > max_depth or url in self.visited:
            return self.results, self._metadata_for_return()

        # Normalize url (remove fragment)
        parsed = urlparse(url)
        normalized = parsed._replace(fragment="").geturl()

        self.visited.add(normalized)
        logging.info(f"[Crawler] (Depth {depth}) Visiting: {normalized}")

        internal_links_to_crawl: List[str] = []

        try:
            response = self.session.get(normalized, timeout=10)
            content_type = response.headers.get("content-type", "").lower()

            if "text/html" in content_type:
                soup = BeautifulSoup(response.text, "html.parser")

                # extract various things
                self.extract_metadata(soup, normalized)
                self.extract_contact_info(soup, response.text)
                self.analyze_content(soup, normalized)

                links, forms = [], []
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    # ignore javascript:, mailto:, tel:
                    if href.startswith(("javascript:", "mailto:", "tel:")):
                        continue
                    link = urljoin(normalized, href)
                    if self.same_domain(link, base):
                        links.append({"url": link, "text": a.get_text(strip=True)})
                        if link not in self.visited:
                            internal_links_to_crawl.append(link)

                for form in soup.find_all("form"):
                    action = form.get("action") or normalized
                    method = form.get("method", "GET").upper()
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inputs.append({"name": inp.get("name", ""), "type": inp.get("type", "text")})
                    forms.append({"action": urljoin(normalized, action), "method": method, "inputs": inputs})

                page_title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
                self.results.append(
                    {
                        "url": normalized,
                        "status": response.status_code,
                        "title": page_title,
                        "links": links,
                        "forms": forms,
                    }
                )
            else:
                # non-html resource: categorize by extension
                path = urlparse(normalized).path
                ext = path.split(".")[-1].lower() if "." in path else ""
                if ext in ["pdf", "doc", "docx"]:
                    self.found_files["documents"].add(normalized)
                elif ext in ["jpg", "jpeg", "png", "gif", "svg", "webp"]:
                    self.found_files["images"].add(normalized)
                else:
                    self.found_files["other"].add(normalized)

        except Exception as e:
            logging.error(f"[Crawler] Failed: {normalized} ({str(e)})")
            # on failure, return current results/metadata to avoid raising in caller
            return self.results, self._metadata_for_return()

        # Continue crawling discovered internal links
        for link in internal_links_to_crawl:
            if link not in self.visited:
                time.sleep(0.5)  # polite delay
                try:
                    self.crawl(link, base, depth + 1, max_depth)
                except Exception:
                    # ignore individual link crawl errors to continue overall crawl
                    continue

        # Return final results after crawl is complete
        return self.results, self._metadata_for_return()

    def same_domain(self, url: str, base: str) -> bool:
        try:
            return urlparse(url).netloc == urlparse(base).netloc
        except Exception:
            return False

    def _metadata_for_return(self) -> Dict:
        """Prepare metadata for return/serialization (convert sets to lists)."""
        meta = dict(self.metadata)
        meta["technologies"] = list(meta.get("technologies", []))
        meta["social_media"] = list(meta.get("social_media", []))
        meta["emails"] = list(meta.get("emails", []))
        meta["phone_numbers"] = list(meta.get("phone_numbers", []))
        meta["found_files"] = {k: list(v) for k, v in self.found_files.items()}
        meta["content_types"] = {k: list(v) for k, v in self.content_types.items()}
        meta["stats"] = dict(self.stats)
        return meta
