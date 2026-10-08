import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


def fetch_html(url):
    """
    Download webpage HTML.
    """

    try:
        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            },
            allow_redirects=True
        )

        if response.status_code == 200:
            return response.text

        return None

    except requests.RequestException:
        return None


def parse_html(html):
    """
    Parse HTML using BeautifulSoup.
    """

    if not html:
        return None

    return BeautifulSoup(html, "html.parser")


# ============================================================
# IFRAME
# ============================================================

def check_iframe(soup):
    """
    Check whether the webpage contains an iframe.

    Returns:
        1  -> iframe detected
        -1 -> no iframe detected
    """

    if soup.find("iframe"):
        return 1

    return -1


# ============================================================
# POPUP WINDOW
# ============================================================

def check_popupwindow(soup):
    """
    Look for JavaScript commonly associated with popup windows.

    Returns:
        1  -> suspicious popup code detected
        -1 -> not detected
    """

    scripts = soup.find_all("script")

    for script in scripts:

        if not script.string:
            continue

        javascript = script.string.lower()

        if "window.open" in javascript:
            return 1

    return -1


# ============================================================
# RIGHT CLICK
# ============================================================

def check_rightclick(soup):
    """
    Check whether the webpage attempts to disable right-click.

    Returns:
        1  -> right-click disabling code detected
        -1 -> not detected
    """

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
# MAIN PAGE ANALYZER
# ============================================================

def get_domain(url):
    """
    Extract the domain from a URL.
    """
    return urlparse(url).netloc.lower()


def is_external_url(resource_url, base_url):
    """
    Check whether a resource belongs to an external domain.
    """

    absolute_url = urljoin(base_url, resource_url)

    base_domain = get_domain(base_url)
    resource_domain = get_domain(absolute_url)

    if not resource_domain:
        return False

    return resource_domain != base_domain


def check_request_url(soup, base_url):
    """
    Analyze images, scripts and media resources.

    Returns:
        1  -> mostly internal resources
        -1 -> many external resources
    """

    resources = []

    # Images
    for tag in soup.find_all("img"):
        src = tag.get("src")

        if src:
            resources.append(src)

    # Scripts
    for tag in soup.find_all("script"):
        src = tag.get("src")

        if src:
            resources.append(src)

    # Media
    for tag in soup.find_all(["audio", "video", "source"]):
        src = tag.get("src")

        if src:
            resources.append(src)

    if not resources:
        return 1

    external_count = sum(
        is_external_url(resource, base_url)
        for resource in resources
    )

    external_ratio = external_count / len(resources)

    if external_ratio > 0.5:
        return -1

    return 1


def check_url_of_anchor(soup, base_url):
    """
    Analyze hyperlinks in <a> tags.
    """

    anchors = soup.find_all("a")

    if not anchors:
        return 1

    external_count = 0
    valid_links = 0

    for anchor in anchors:

        href = anchor.get("href")

        if not href:
            continue

        if href.startswith("#"):
            continue

        absolute_url = urljoin(base_url, href)

        if absolute_url.startswith(("http://", "https://")):

            valid_links += 1

            if is_external_url(absolute_url, base_url):
                external_count += 1

    if valid_links == 0:
        return 1

    ratio = external_count / valid_links

    if ratio > 0.5:
        return -1

    elif ratio > 0:
        return 0

    return 1


def check_links_in_tags(soup, base_url):
    """
    Analyze links in <link> and <script> tags.
    """

    resources = []

    for tag in soup.find_all("link"):

        href = tag.get("href")

        if href:
            resources.append(href)

    for tag in soup.find_all("script"):

        src = tag.get("src")

        if src:
            resources.append(src)

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

def analyze_page(url):

    html = fetch_html(url)

    if html is None:
        return None

    soup = parse_html(html)

    features = {}

    features["iframe"] = check_iframe(soup)

    features["popupwindow"] = check_popupwindow(soup)

    features["rightclick"] = check_rightclick(soup)

    features["request_url"] = check_request_url(
        soup,
        url
    )

    features["url_of_anchor"] = check_url_of_anchor(
        soup,
        url
    )

    features["links_in_tags"] = check_links_in_tags(
        soup,
        url
    )

    return features
# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://example.com"

    features = analyze_page(test_url)

    print("URL:", test_url)

    print("\nHTML Features:")

    if features:

        for name, value in features.items():

            print(f"{name}: {value}")

    else:

        print("Could not analyze webpage.")
from urllib.parse import urlparse, urljoin


def get_domain(url):
    """
    Extract the domain from a URL.
    """

    return urlparse(url).netloc.lower()


def is_external_url(resource_url, base_url):
    """
    Check whether a resource belongs to an external domain.
    """

    absolute_url = urljoin(base_url, resource_url)

    base_domain = get_domain(base_url)
    resource_domain = get_domain(absolute_url)

    if not resource_domain:
        return False

    return resource_domain != base_domain


def check_request_url(soup, base_url):
    """
    Analyze images, scripts and other resources.

    Returns:
        1  -> mostly internal resources
        -1 -> many external resources
    """

    resources = []

    # Images
    for tag in soup.find_all("img"):
        src = tag.get("src")
        if src:
            resources.append(src)

    # Scripts
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            resources.append(src)

    # Media
    for tag in soup.find_all(["audio", "video", "source"]):
        src = tag.get("src")
        if src:
            resources.append(src)

    if not resources:
        return 1

    external_count = sum(
        is_external_url(resource, base_url)
        for resource in resources
    )

    external_ratio = external_count / len(resources)

    if external_ratio > 0.5:
        return -1

    return 1


def check_url_of_anchor(soup, base_url):
    """
    Analyze hyperlinks in <a> tags.

    Returns:
        1  -> mostly internal/safe-looking links
        0  -> mixed links
        -1 -> mostly external links
    """

    anchors = soup.find_all("a")

    if not anchors:
        return 1

    external_count = 0
    valid_links = 0

    for anchor in anchors:

        href = anchor.get("href")

        if not href:
            continue

        if href.startswith("#"):
            continue

        absolute_url = urljoin(base_url, href)

        if absolute_url.startswith(("http://", "https://")):

            valid_links += 1

            if is_external_url(absolute_url, base_url):
                external_count += 1

    if valid_links == 0:
        return 1

    ratio = external_count / valid_links

    if ratio > 0.5:
        return -1

    elif ratio > 0:
        return 0

    return 1


def check_links_in_tags(soup, base_url):
    """
    Analyze links in <link> and <script> tags.

    Returns:
        1  -> mostly internal
        0  -> mixed
        -1 -> mostly external
    """

    resources = []

    # <link href="...">
    for tag in soup.find_all("link"):

        href = tag.get("href")

        if href:
            resources.append(href)

    # <script src="...">
    for tag in soup.find_all("script"):

        src = tag.get("src")

        if src:
            resources.append(src)

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