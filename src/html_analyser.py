import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


# ============================================================
# FETCH HTML
# ============================================================

def fetch_html(url):
    """Download webpage HTML."""

    try:
        response = requests.get(
            url,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True
        )

        if response.status_code == 200:
            return response.text

        return None

    except requests.RequestException:
        return None


def parse_html(html):
    """Parse HTML using BeautifulSoup."""

    if not html:
        return None

    return BeautifulSoup(html, "html.parser")


# ============================================================
# DOMAIN HELPERS
# ============================================================

def get_domain(url):
    """Extract hostname from a URL."""

    hostname = (urlparse(url).hostname or "").lower()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname


def is_external_url(resource_url, base_url):
    """Check whether a resource belongs to another hostname."""

    absolute_url = urljoin(base_url, resource_url)

    base_domain = get_domain(base_url)
    resource_domain = get_domain(absolute_url)

    if not resource_domain or not base_domain:
        return False

    return resource_domain != base_domain


# ============================================================
# IFRAME
# ============================================================

def check_iframe(soup):
    """Detect iframe elements."""

    return 1 if soup.find("iframe") else -1


# ============================================================
# POPUP WINDOW
# ============================================================

def check_popupwindow(soup):
    """Detect common JavaScript popup calls."""

    for script in soup.find_all("script"):
        javascript = script.get_text(" ", strip=True).lower()

        if "window.open" in javascript:
            return 1

    return -1


# ============================================================
# RIGHT CLICK
# ============================================================

def check_rightclick(soup):
    """Detect common right-click disabling patterns."""

    html = str(soup).lower()

    suspicious_patterns = [
        "contextmenu",
        "event.button==2",
        "event.button == 2",
        "which==3",
        "which == 3"
    ]

    for pattern in suspicious_patterns:
        if pattern in html:
            return 1

    return -1


# ============================================================
# REQUEST URL
# ============================================================

def check_request_url(soup, base_url):
    """Estimate whether images, scripts and media use external URLs."""

    resources = []

    for tag in soup.find_all("img"):
        if tag.get("src"):
            resources.append(tag["src"])

    for tag in soup.find_all("script"):
        if tag.get("src"):
            resources.append(tag["src"])

    for tag in soup.find_all(["audio", "video", "source"]):
        if tag.get("src"):
            resources.append(tag["src"])

    if not resources:
        return 1

    external_count = sum(
        is_external_url(resource, base_url)
        for resource in resources
    )

    external_ratio = external_count / len(resources)

    return -1 if external_ratio > 0.5 else 1


# ============================================================
# URL OF ANCHOR
# ============================================================

def check_url_of_anchor(soup, base_url):
    """Analyze whether anchor links point to external hosts."""

    anchors = soup.find_all("a")
    valid_links = []

    for anchor in anchors:
        href = anchor.get("href")

        if not href:
            continue

        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        absolute_url = urljoin(base_url, href)

        if urlparse(absolute_url).scheme in ("http", "https"):
            valid_links.append(absolute_url)

    if not valid_links:
        return 1

    external_count = sum(
        is_external_url(link, base_url)
        for link in valid_links
    )

    ratio = external_count / len(valid_links)

    if ratio > 0.5:
        return -1
    elif ratio > 0:
        return 0

    return 1


# ============================================================
# LINKS IN TAGS
# ============================================================

def check_links_in_tags(soup, base_url):
    """Analyze external resources in link and script tags."""

    resources = []

    for tag in soup.find_all("link"):
        if tag.get("href"):
            resources.append(tag["href"])

    for tag in soup.find_all("script"):
        if tag.get("src"):
            resources.append(tag["src"])

    if not resources:
        return 1

    external_count = sum(
        is_external_url(resource, base_url)
        for resource in resources
    )

    ratio = external_count / len(resources)

    if ratio > 0.5:
        return -1
    elif ratio > 0:
        return 0

    return 1


# ============================================================
# SFH - SERVER FORM HANDLER
# ============================================================

def check_sfh(soup, base_url):
    """
    Prototype heuristic:
    1  = forms submit to the same hostname
    0  = no form or unknown action
    -1 = external hostname
    """

    forms = soup.find_all("form")

    if not forms:
        return 0

    base_domain = get_domain(base_url)

    for form in forms:
        action = form.get("action")

        if not action:
            return 0

        action_url = urljoin(base_url, action)
        action_domain = get_domain(action_url)

        if action_domain and action_domain != base_domain:
            return -1

    return 1


# ============================================================
# SUBMITTING TO EMAIL
# ============================================================

def check_submitting_to_email(soup):
    """Detect forms that submit through a mailto action."""

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip().lower()

        if action.startswith("mailto:") or "mailto:" in action:
            return -1

    return 1


# ============================================================
# ON MOUSEOVER
# ============================================================

def check_on_mouseover(soup):
    """Detect onmouseover event attributes."""

    for tag in soup.find_all(True):
        if tag.has_attr("onmouseover"):
            return -1

    return 1


# ============================================================
# ABNORMAL URL
# ============================================================

def check_abnormal_url(soup, base_url):
    """Detect form actions that point to another hostname."""

    base_domain = get_domain(base_url)

    for form in soup.find_all("form"):
        action = form.get("action")

        if not action:
            continue

        action_url = urljoin(base_url, action)
        action_domain = get_domain(action_url)

        if action_domain and action_domain != base_domain:
            return -1

    return 1


# ============================================================
# MAIN PAGE ANALYZER
# ============================================================

def analyze_page(url):
    """Fetch a webpage and return its HTML-related features."""

    html = fetch_html(url)

    if html is None:
        return None

    soup = parse_html(html)

    if soup is None:
        return None

    features = {
        "iframe": check_iframe(soup),
        "popupwindow": check_popupwindow(soup),
        "rightclick": check_rightclick(soup),
        "request_url": check_request_url(soup, url),
        "url_of_anchor": check_url_of_anchor(soup, url),
        "links_in_tags": check_links_in_tags(soup, url),
        "sfh": check_sfh(soup, url),
        "submitting_to_email": check_submitting_to_email(soup),
        "on_mouseover": check_on_mouseover(soup),
        "abnormal_url": check_abnormal_url(soup, url)
    }

    return features


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://example.com"

    features = analyze_page(test_url)

    print("URL:", test_url)
    print("\nHTML Features:")

    if features is not None:
        for name, value in features.items():
            print(f"{name}: {value}")
    else:
        print("Could not analyze webpage.")