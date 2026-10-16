from shared.public_source import _allowed_https_url


def test_nvd_is_an_allowlisted_https_source():
    assert _allowed_https_url("https://nvd.nist.gov/vuln/detail/CVE-2022-40769")


def test_source_allowlist_rejects_untrusted_hosts_and_non_https():
    assert not _allowed_https_url("https://nvd.nist.gov.attacker.example/vuln/detail/CVE-2022-40769")
    assert not _allowed_https_url("http://nvd.nist.gov/vuln/detail/CVE-2022-40769")
