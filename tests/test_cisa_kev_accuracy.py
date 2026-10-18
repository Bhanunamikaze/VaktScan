import asyncio
from unittest import mock

from modules import cisa_kev


def test_kev_annotates_without_duplicate_or_severity_inflation():
    findings = [{
        "status": "VULNERABLE",
        "vulnerability": "CVE-2020-11023 - jquery 3.0.0",
        "target": "app.example.com",
        "severity": "MEDIUM",
        "details": "Version evidence only; exploitability is conditional.",
    }]
    catalog = {"vulnerabilities": [{
        "cveID": "CVE-2020-11023",
        "vulnerabilityName": "jQuery XSS",
        "vendorProject": "jQuery",
        "product": "jQuery",
        "requiredAction": "Update",
        "dueDate": "2025-02-13",
        "knownRansomwareCampaignUse": "Unknown",
    }]}

    async def run():
        with mock.patch.object(
            cisa_kev,
            "fetch_kev_catalog",
            new=mock.AsyncMock(return_value=catalog),
        ):
            return await cisa_kev.enrich_findings_with_kev(findings)

    result = asyncio.run(run())
    assert result is findings
    assert len(result) == 1
    assert result[0]["severity"] == "MEDIUM"
    assert result[0]["status"] == "VULNERABLE"
    assert result[0]["cisa_kev_ids"] == ["CVE-2020-11023"]
    assert "CISA KEV: CVE-2020-11023 is known exploited" in result[0]["details"]
