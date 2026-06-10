import re


def extract_iocs(strings):
    """
    Extraction simple des IOC :
    - IP
    - domaines
    - URLs
    - chemins Linux
    - services/systemd
    - fichiers suspects
    """

    text = "\n".join(strings)

    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    url_regex = r"https?://[^\s\"']+"
    domain_regex = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    path_regex = r"\/(?:[A-Za-z0-9._-]+\/?)+"
    service_regex = r"\b[a-zA-Z0-9_.-]+\.service\b"

    iocs = {
        "ips": list(set(re.findall(ip_regex, text))),
        "urls": list(set(re.findall(url_regex, text))),
        "domains": list(set(re.findall(domain_regex, text))),
        "paths": list(set(re.findall(path_regex, text))),
        "services": list(set(re.findall(service_regex, text))),
        "suspicious_files": []
    }

    suspicious_extensions = [".sh", ".so", ".ko", ".elf", ".bin"]

    for s in strings:
        for ext in suspicious_extensions:
            if ext in s:
                iocs["suspicious_files"].append(s)

    iocs["suspicious_files"] = list(set(iocs["suspicious_files"]))

    return iocs
