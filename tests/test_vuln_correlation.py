import os
import time
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from modules.nvd import extract_product_and_version
from modules.nmap_runner import NmapRunner
from modules.nuclei_runner import sync_nuclei_templates

def test_extract_product_and_version():
    # SSH banner checks
    f1 = {"port": 22, "details": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "vulnerability": "SSH service"}
    prod, ver = extract_product_and_version(f1)
    assert prod == "openssh"
    assert ver == "8.2p1"

    f2 = {"port": 22, "details": "SSH-2.0-dropbear_2020.81", "vulnerability": "SSH service"}
    prod, ver = extract_product_and_version(f2)
    assert prod == "dropbear"
    assert ver == "2020.81"

    # FTP banner checks
    f3 = {"port": 21, "details": "220 (vsFTPd 3.0.3)", "vulnerability": "FTP service"}
    prod, ver = extract_product_and_version(f3)
    assert prod == "vsftpd"
    assert ver == "3.0.3"

    f4 = {"port": 21, "details": "220 ProFTPD 1.3.5a Server", "vulnerability": "FTP service"}
    prod, ver = extract_product_and_version(f4)
    assert prod == "proftpd"
    assert ver == "1.3.5a"

    # MySQL version checks
    f5 = {"port": 3306, "details": "5.7.29-0ubuntu0.18.04.1", "vulnerability": "MySQL Server"}
    prod, ver = extract_product_and_version(f5)
    assert prod == "mysql"
    assert ver == "5.7.29"

    # Redis version checks
    f6 = {"port": 6379, "details": "redis_version:6.0.5", "vulnerability": "Redis Server"}
    prod, ver = extract_product_and_version(f6)
    assert prod == "redis"
    assert ver == "6.0.5"

    # Tomcat details checks
    f7 = {"port": 8080, "details": "Apache Tomcat/9.0.37", "vulnerability": "HTTP web server"}
    prod, ver = extract_product_and_version(f7)
    assert prod == "tomcat"
    assert ver == "9.0.37"

    # Nginx details checks
    f8 = {"port": 80, "details": "Server: nginx/1.18.0", "vulnerability": "HTTP web server"}
    prod, ver = extract_product_and_version(f8)
    assert prod == "nginx"
    assert ver == "1.18.0"


def test_parse_nmap_xml_vulners():
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script vuln,cve -Pn -p 80 127.0.0.1" start="1622568000" version="7.91" xmloutputversion="1.04">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/>
        <script id="vulners" output="&#xa;  cpe:/a:apache:http_server:2.4.41: &#xa;    CVE-2020-11984&#x9;7.5&#x9;https://vulners.com/cve/CVE-2020-11984&#x9;*EXPLOIT*&#xa;">
          <table name="cpe:/a:apache:http_server:2.4.41">
            <table>
              <elem key="id">CVE-2020-11984</elem>
              <elem key="cvss">7.5</elem>
              <elem key="type">cve</elem>
              <elem key="is_exploit">true</elem>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        xml_path = f.name

    try:
        runner = NmapRunner()
        findings = runner.parse_nmap_xml(xml_path, "localhost", "127.0.0.1")
        assert len(findings) == 1
        f = findings[0]
        assert "CVE-2020-11984" in f["vulnerability"]
        assert f["port"] == "80"
        assert f["status"] == "VULNERABLE"
        assert f["severity"] == "HIGH"
        assert f["service_version"] == "2.4.41"
    finally:
        os.remove(xml_path)


def test_parse_nmap_xml_general():
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script vuln,cve -Pn -p 8080 127.0.0.1" start="1622568000" version="7.91" xmloutputversion="1.04">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="Apache Tomcat" version="8.5.50" method="probed" conf="10"/>
        <script id="http-vuln-cve2017-12617" output="&#xa;  Vulnerable:&#xa;  CVE: CVE-2017-12617&#xa;  CVSS Score: 8.5&#xa;"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        xml_path = f.name

    try:
        runner = NmapRunner()
        findings = runner.parse_nmap_xml(xml_path, "127.0.0.1", "127.0.0.1")
        assert len(findings) == 1
        f = findings[0]
        assert "CVE-2017-12617" in f["vulnerability"]
        assert f["port"] == "8080"
        assert f["status"] == "VULNERABLE"
        assert f["severity"] == "HIGH"
        assert f["service_version"] == "8.5.50"
    finally:
        os.remove(xml_path)


@patch('subprocess.run')
def test_sync_nuclei_templates_cache(mock_run):
    sync_file = os.path.expanduser('~/.nuclei_last_sync')
    
    # 1. Test skip sync if modified within 7 days
    if os.path.exists(sync_file):
        os.remove(sync_file)
        
    with open(sync_file, 'w') as f:
        f.write(str(time.time()))
        
    mock_run.reset_mock()
    sync_nuclei_templates(force=False)
    mock_run.assert_not_called()

    # 2. Test force sync ignores cache
    mock_run.reset_mock()
    mock_run.return_value = MagicMock(returncode=0)
    sync_nuclei_templates(force=True)
    mock_run.assert_called_once()


@pytest.mark.asyncio
async def test_lookup_cves_nvd():
    from modules.nvd import lookup_cves
    
    mock_response_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-38606",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    },
                    "descriptions": [
                        {"lang": "en", "value": "A malicious exploit on Apple macOS and iOS."}
                    ]
                }
            }
        ]
    }
    
    class MockResponse:
        def __init__(self, json_data, status_code):
            self._json_data = json_data
            self.status_code = status_code
        def json(self):
            return self._json_data

    # Test CPE match first path
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = MockResponse(mock_response_data, 200)
        findings = await lookup_cves("ios", "16.5", target="apple.com", resolved_ip="127.0.0.1", port="443")
        assert len(findings) == 1
        f = findings[0]
        assert f["status"] == "CRITICAL"
        assert f["severity"] == "CRITICAL"
        assert "CVE-2023-38606" in f["vulnerability"]
        assert f["target"] == "apple.com"
        assert f["resolved_ip"] == "127.0.0.1"
        assert f["port"] == "443"
        assert f["module"] == "nvd"

    # Test Fallback keyword search path (first request fails with 404, second succeeds with 200)
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.side_effect = [
            MockResponse({}, 404),
            MockResponse(mock_response_data, 200)
        ]
        findings = await lookup_cves("ios", "16.5", target="apple.com", resolved_ip="127.0.0.1", port="443")
        assert len(findings) == 1
        assert "CVE-2023-38606" in findings[0]["vulnerability"]

    # Test completely unreachable or error status codes
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = MockResponse({}, 500)
        findings = await lookup_cves("ios", "16.5")
        assert findings == []


def test_parse_nmap_xml_no_vulns():
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -Pn -p 80 127.0.0.1" start="1622568000" version="7.91" xmloutputversion="1.04">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        xml_path = f.name

    try:
        runner = NmapRunner()
        findings = runner.parse_nmap_xml(xml_path, "localhost", "127.0.0.1")
        assert findings == []
    finally:
        os.remove(xml_path)


def test_extract_product_and_version_edge_cases():
    # Empty finding
    prod, ver = extract_product_and_version({})
    assert prod == ""
    assert ver == ""

    # Finding with product key set
    f1 = {"port": 80, "product": "apache", "vulnerability": "Apache HTTP Server"}
    prod, ver = extract_product_and_version(f1)
    assert prod == "apache"
    assert ver == ""

    # Finding with specific ssh keywords/details
    f2 = {"port": 22, "details": "SSH-2.0-OpenSSH_9.0", "vulnerability": "SSH service"}
    prod, ver = extract_product_and_version(f2)
    assert prod == "openssh"
    assert ver == "9.0"


def test_parse_nmap_xml_corrupted_or_junk():
    # Test case 1: XML file has trailing junk (junk after document element)
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script vuln,cve -Pn -p 80 127.0.0.1" start="1622568000" version="7.91" xmloutputversion="1.04">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/>
        <script id="http-vuln-cve2017-12617" output="&#xa;  Vulnerable:&#xa;  CVE: CVE-2017-12617&#xa;  CVSS Score: 8.5&#xa;"/>
      </port>
    </ports>
  </host>
</nmaprun>
nstats>
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        xml_path = f.name

    try:
        runner = NmapRunner()
        findings = runner.parse_nmap_xml(xml_path, "127.0.0.1", "127.0.0.1")
        assert len(findings) == 1
        assert "CVE-2017-12617" in findings[0]["vulnerability"]
    finally:
        os.remove(xml_path)

    # Test case 2: XML file is missing closing tags (interrupted run)
    xml_content_truncated = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script vuln,cve -Pn -p 80 127.0.0.1" start="1622568000" version="7.91" xmloutputversion="1.04">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/>
        <script id="http-vuln-cve2017-12617" output="&#xa;  Vulnerable:&#xa;  CVE: CVE-2017-12617&#xa;  CVSS Score: 8.5&#xa;"/>
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content_truncated)
        xml_path = f.name

    try:
        runner = NmapRunner()
        findings = runner.parse_nmap_xml(xml_path, "127.0.0.1", "127.0.0.1")
        assert len(findings) == 1
        assert "CVE-2017-12617" in findings[0]["vulnerability"]
    finally:
        os.remove(xml_path)



