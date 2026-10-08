from urllib.parse import urlparse
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
import whois


# ============================================================
# FEATURE NAMES
# ============================================================

FEATURE_NAMES = [
    "having_ip_address",
    "url_length",
    "shortening_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "sslfinal_state",
    "domain_registration_length",
    "favicon",
    "port",
    "https_token",
    "request_url",
    "url_of_anchor",
    "links_in_tags",
    "sfh",
    "submitting_to_email",
    "abnormal_url",
    "redirect",
    "on_mouseover",
    "rightclick",
    "popupwindow",
    "iframe",
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report"
]


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):
    """
    Ensure the URL has a scheme so urlparse()
    can correctly identify the domain.
    """

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


# ============================================================
# DNS FEATURE
# ============================================================

def check_dns_record(hostname):
    """
    Check whether the hostname resolves through DNS.

    Returns:
        1  -> DNS record exists
        -1 -> DNS lookup failed
    """

    try:
        socket.gethostbyname(hostname)
        return 1

    except (socket.gaierror, socket.timeout):
        return -1


# ============================================================
# SSL FEATURE
# ============================================================

def check_ssl_state(hostname):
    """
    Check whether HTTPS can establish a valid TLS connection.

    Returns:
        1  -> valid HTTPS/TLS connection
        0  -> certificate could not be verified
        -1 -> HTTPS connection failed
    """

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                secure_sock.getpeercert()

                return 1

    except ssl.SSLCertVerificationError:

        return 0

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionError,
        OSError
    ):

        return -1


# ============================================================
# DOMAIN AGE FEATURE
# ============================================================

def get_domain_age(hostname):
    """
    Estimate whether the domain is established.

    Returns:
        1  -> domain appears established
        -1 -> domain appears young
         0 -> information unavailable
    """

    try:

        info = whois.whois(hostname)

        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not isinstance(creation_date, datetime):
            return 0

        # Handle timezone-aware and naive datetime objects
        if creation_date.tzinfo is None:

            current_time = datetime.utcnow()

        else:

            current_time = datetime.now(timezone.utc)

        age_days = (
            current_time - creation_date
        ).days

        if age_days >= 180:

            return 1

        else:

            return -1

    except Exception:

        return 0


# ============================================================
# DOMAIN REGISTRATION LENGTH
# ============================================================

def get_registration_length(hostname):
    """
    Estimate the domain registration period from WHOIS data.

    Returns:
        1  -> registration period appears long
        -1 -> registration period appears short
         0 -> information unavailable
    """

    try:

        info = whois.whois(hostname)

        creation_date = info.creation_date
        expiration_date = info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if not isinstance(creation_date, datetime):
            return 0

        if not isinstance(expiration_date, datetime):
            return 0

        # Make both datetimes comparable
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        if expiration_date.tzinfo is None:
            expiration_date = expiration_date.replace(
                tzinfo=timezone.utc
            )

        registration_days = (
            expiration_date - creation_date
        ).days

        if registration_days >= 365:

            return 1

        else:

            return -1

    except Exception:

        return 0


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):
    """
    Extract features that can currently be calculated
    from the URL and domain/network information.
    """

    # Normalize URL
    url = normalize_url(url)

    # Parse URL
    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""

    # Create feature dictionary FIRST
    features = {}


    # ========================================================
    # 1. HAVING IP ADDRESS
    # ========================================================

    try:

        ipaddress.ip_address(hostname)

        features["having_ip_address"] = 1

    except ValueError:

        features["having_ip_address"] = -1


    # ========================================================
    # 2. URL LENGTH
    # ========================================================

    if len(url) < 54:

        features["url_length"] = 1

    elif len(url) <= 75:

        features["url_length"] = 0

    else:

        features["url_length"] = -1


    # ========================================================
    # 3. SHORTENING SERVICE
    # ========================================================

    shortening_services = [

        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly"

    ]

    features["shortening_service"] = (

        -1
        if any(
            service in hostname
            for service in shortening_services
        )
        else 1

    )


    # ========================================================
    # 4. @ SYMBOL
    # ========================================================

    features["having_at_symbol"] = (

        -1
        if "@" in url
        else 1

    )


    # ========================================================
    # 5. DOUBLE SLASH REDIRECTING
    # ========================================================

    remainder = url.split("://", 1)[-1]

    features["double_slash_redirecting"] = (

        -1
        if "//" in remainder
        else 1

    )


    # ========================================================
    # 6. PREFIX / SUFFIX
    # ========================================================

    features["prefix_suffix"] = (

        -1
        if "-" in hostname
        else 1

    )


    # ========================================================
    # 7. SUBDOMAIN
    # ========================================================

    parts = hostname.split(".")

    if len(parts) <= 2:

        features["having_sub_domain"] = 1

    elif len(parts) == 3:

        features["having_sub_domain"] = 0

    else:

        features["having_sub_domain"] = -1


    # ========================================================
    # 8. SSL FINAL STATE
    # ========================================================

    if parsed.scheme == "https":

        features["sslfinal_state"] = check_ssl_state(
            hostname
        )

    else:

        features["sslfinal_state"] = -1


    # ========================================================
    # 9. DOMAIN REGISTRATION LENGTH
    # ========================================================

    features["domain_registration_length"] = (
        get_registration_length(hostname)
    )


    # ========================================================
    # 10. FAVICON
    # ========================================================

    # Not implemented yet
    features["favicon"] = None


    # ========================================================
    # 11. PORT
    # ========================================================

    port = parsed.port

    if port is None:

        features["port"] = 0

    elif port in (80, 443):

        features["port"] = 0

    else:

        features["port"] = 1


    # ========================================================
    # 12. HTTPS TOKEN
    # ========================================================

    features["https_token"] = (

        -1
        if "https" in hostname.lower()
        else 1

    )


    # ========================================================
    # WEBPAGE FEATURES
    # ========================================================

    features["request_url"] = None
    features["url_of_anchor"] = None
    features["links_in_tags"] = None
    features["sfh"] = None
    features["submitting_to_email"] = None
    features["abnormal_url"] = None
    features["redirect"] = None
    features["on_mouseover"] = None
    features["rightclick"] = None
    features["popupwindow"] = None
    features["iframe"] = None


    # ========================================================
    # DOMAIN FEATURES
    # ========================================================

    features["age_of_domain"] = get_domain_age(
        hostname
    )

    features["dnsrecord"] = check_dns_record(
        hostname
    )


    # ========================================================
    # EXTERNAL REPUTATION FEATURES
    # ========================================================

    features["web_traffic"] = None
    features["page_rank"] = None
    features["google_index"] = None
    features["links_pointing_to_page"] = None
    features["statistical_report"] = None


    # ========================================================
    # RETURN FEATURES IN EXACT MODEL ORDER
    # ========================================================

    return {
        feature: features.get(feature, None)
        for feature in FEATURE_NAMES
    }


# ============================================================
# VALIDATION
# ============================================================

def validate_features(features):
    """
    Make sure all expected feature names exist.
    """

    missing = [

        feature
        for feature in FEATURE_NAMES
        if feature not in features

    ]

    if missing:

        raise ValueError(
            f"Missing features: {missing}"
        )

    return True


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://example.com/login"

    features = extract_url_features(test_url)

    print("URL:", test_url)

    print("\nExtracted features:")

    for name, value in features.items():

        print(f"{name}: {value}")

    print("\nFeature count:", len(features))

    validate_features(features)

    print("Feature validation: PASSED")