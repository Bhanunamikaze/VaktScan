"""
VaktScan Service Recon Module
Port-specific recon and vulnerability checks drawn directly from AutoRecon methodology.
Each check mirrors the exact tool invocations from AutoRecon.sh — tested logic, same tools.

Covers: FTP, SSH, SMTP, DNS, Kerberos, RPC, NTP, SMB, SNMP, LDAP, MySQL, PostgreSQL,
        Redis, MongoDB, CouchDB, Memcached, Docker API, Kubernetes, Jenkins,
        Jolokia, AJP (Ghostcat), WinRM, VNC, NFS, Rsync, ActiveMQ/AMQP,
        Cassandra, VMware ESXi, MSSQL, Oracle, RDP.
"""

import asyncio
import os
import re
import shutil

import httpx

MODULE_NAME = 'ServiceRecon'


def _finding(status, severity, vulnerability, details, target, resolved_ip, port,
             url='', payload_url='', service_version='',
             http_status='N/A', page_title='N/A', content_length='N/A'):
    return {
        'status': status,
        'vulnerability': vulnerability,
        'target': target,
        'resolved_ip': resolved_ip,
        'port': port,
        'url': url or f'{target}:{port}',
        'payload_url': payload_url or url or f'{target}:{port}',
        'module': MODULE_NAME,
        'service_version': service_version,
        'severity': severity,
        'details': details,
        'http_status': str(http_status),
        'page_title': page_title,
        'content_length': str(content_length),
    }


async def _run(cmd, timeout=30):
    """Run a command, return (stdout, stderr, returncode). None on exception."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'), proc.returncode
    except Exception:
        return None, None, -1


def _bin(name):
    return shutil.which(name)


# ─── FTP (21) ─────────────────────────────────────────────────────────────────

async def check_ftp(host, port, target, resolved_ip):
    out = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        banner = (await asyncio.wait_for(reader.read(256), timeout=3)).decode('utf-8', errors='replace').strip()
        writer.write(b'USER anonymous\r\n')
        await writer.drain()
        await asyncio.wait_for(reader.read(256), timeout=3)
        writer.write(b'PASS anonymous@\r\n')
        await writer.drain()
        resp = (await asyncio.wait_for(reader.read(256), timeout=3)).decode('utf-8', errors='replace')
        writer.close()
        if '230' in resp:
            out.append(_finding('VULNERABLE', 'HIGH', 'FTP Anonymous Login Allowed',
                f'FTP accepts anonymous:anonymous@ login. Banner: {banner[:120]}',
                target, resolved_ip, port, url=f'ftp://{host}:{port}'))
        else:
            out.append(_finding('INFO', 'INFO', 'FTP Service Detected',
                f'FTP banner: {banner[:200]}',
                target, resolved_ip, port, url=f'ftp://{host}:{port}'))
    except Exception:
        pass
    return out


# ─── SSH (22) ─────────────────────────────────────────────────────────────────

async def check_ssh(host, port, target, resolved_ip):
    out = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        banner = (await asyncio.wait_for(reader.read(256), timeout=3)).decode('utf-8', errors='replace').strip()
        writer.close()
        out.append(_finding('INFO', 'INFO', 'SSH Service Detected',
            f'SSH banner: {banner[:200]}',
            target, resolved_ip, port, url=f'ssh://{host}:{port}'))
    except Exception:
        pass

    if _bin('ssh-audit'):
        stdout, _, _ = await _run(['ssh-audit', '-p', str(port), host], timeout=30)
        if stdout:
            issues = [l for l in stdout.splitlines()
                      if any(w in l.lower() for w in ('warn', 'fail', 'crit', 'vuln', 'weak'))]
            if issues:
                out.append(_finding('POTENTIAL', 'MEDIUM', 'SSH Weak Configuration Detected',
                    'ssh-audit findings:\n' + '\n'.join(issues[:10]),
                    target, resolved_ip, port, url=f'ssh://{host}:{port}'))
    return out


# ─── SMTP (25 / 465 / 587) ───────────────────────────────────────────────────

async def check_smtp(host, port, target, resolved_ip):
    out = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        banner = (await asyncio.wait_for(reader.read(512), timeout=3)).decode('utf-8', errors='replace').strip()
        writer.write(b'VRFY root\r\n')
        await writer.drain()
        vrfy = (await asyncio.wait_for(reader.read(256), timeout=3)).decode('utf-8', errors='replace').strip()
        writer.close()
        out.append(_finding('INFO', 'INFO', 'SMTP Service Detected',
            f'SMTP banner: {banner[:200]}',
            target, resolved_ip, port, url=f'smtp://{host}:{port}'))
        if vrfy.startswith('2'):
            out.append(_finding('VULNERABLE', 'MEDIUM', 'SMTP VRFY User Enumeration Enabled',
                f'VRFY root response: {vrfy[:120]} — user enumeration possible.',
                target, resolved_ip, port, url=f'smtp://{host}:{port}'))
    except Exception:
        pass

    # smtp-user-enum (AutoRecon: smtp-user-enum -U unix_users.txt -t HOST)
    if _bin('smtp-user-enum'):
        wordlist = '/usr/share/wordlists/metasploit/unix_users.txt'
        if os.path.exists(wordlist):
            stdout, _, _ = await _run(
                ['smtp-user-enum', '-M', 'VRFY', '-U', wordlist, '-t', host, '-p', str(port)],
                timeout=60)
            if stdout and 'exists' in stdout.lower():
                users = [l for l in stdout.splitlines() if 'exists' in l.lower()]
                out.append(_finding('VULNERABLE', 'MEDIUM', 'SMTP Valid Users Enumerated',
                    'smtp-user-enum found: ' + '; '.join(users[:5]),
                    target, resolved_ip, port, url=f'smtp://{host}:{port}'))
    return out


# ─── DNS (53) ────────────────────────────────────────────────────────────────

async def check_dns(host, port, target, resolved_ip):
    out = []
    # AutoRecon: host -l HOST DNSSERVER
    if _bin('host'):
        stdout, _, rc = await _run(['host', '-l', host, host], timeout=10)
        if rc == 0 and stdout and 'has address' in stdout.lower():
            out.append(_finding('VULNERABLE', 'HIGH', 'DNS Zone Transfer Allowed (AXFR)',
                f'Zone transfer succeeded from {host}:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'dns://{host}:{port}'))

    # AutoRecon: dnsrecon -r SUBNET/24 -n DNSSERVER
    if _bin('dnsrecon') and resolved_ip:
        subnet = '.'.join(resolved_ip.split('.')[:3]) + '.0/24'
        stdout, _, _ = await _run(['dnsrecon', '-r', subnet, '-n', host], timeout=30)
        if stdout and 'found' in stdout.lower():
            out.append(_finding('INFO', 'INFO', 'DNS Reverse Lookup Enumeration',
                f'dnsrecon results: {stdout[:400]}',
                target, resolved_ip, port, url=f'dns://{host}:{port}'))
    return out


# ─── Kerberos (88) ───────────────────────────────────────────────────────────

async def check_kerberos(host, port, target, resolved_ip):
    out = []
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.close()
        out.append(_finding('INFO', 'INFO', 'Kerberos KDC Detected',
            f'Kerberos port {port} open on {host} — likely Active Directory environment.',
            target, resolved_ip, port, url=f'kerberos://{host}:{port}'))
    except Exception:
        pass
    return out


# ─── RPC (111 / 135 / 593) ───────────────────────────────────────────────────

async def check_rpc(host, port, target, resolved_ip):
    out = []
    # AutoRecon: rpcinfo -p HOST
    if _bin('rpcinfo'):
        stdout, _, rc = await _run(['rpcinfo', '-p', host], timeout=10)
        if rc == 0 and stdout:
            out.append(_finding('INFO', 'INFO', 'RPC Services Enumerated',
                f'rpcinfo -p output:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'rpc://{host}:{port}'))

    # AutoRecon: rpcclient -U "" -N HOST -c 'srvinfo; enumdomusers; ...'
    if _bin('rpcclient'):
        stdout, _, rc = await _run(
            ['rpcclient', '-U', '', '-N', host, '-c', 'srvinfo'],
            timeout=10)
        if rc == 0 and stdout and 'domain' in stdout.lower():
            out.append(_finding('VULNERABLE', 'HIGH', 'RPC Null Session Allowed',
                f'rpcclient null session succeeded:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'rpc://{host}:{port}'))
    return out


# ─── NTP (123) ───────────────────────────────────────────────────────────────

async def check_ntp(host, port, target, resolved_ip):
    out = []
    # AutoRecon: nmap -sV -Pn --script "ntp* and (discovery or vuln)" -p PORT HOST
    if _bin('nmap'):
        stdout, _, rc = await _run(
            ['nmap', '-sV', '-Pn', '--script', 'ntp-info', '-p', str(port), host],
            timeout=30)
        if rc == 0 and stdout and 'ntp' in stdout.lower():
            out.append(_finding('INFO', 'INFO', 'NTP Service Information Disclosed',
                f'nmap ntp-info:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'ntp://{host}:{port}'))
    return out


# ─── SMB (139 / 445) ─────────────────────────────────────────────────────────

async def check_smb(host, port, target, resolved_ip):
    out = []
    # AutoRecon: smbmap -H HOST
    if _bin('smbmap'):
        stdout, _, _ = await _run(['smbmap', '-H', host], timeout=20)
        if stdout:
            if any(w in stdout.lower() for w in ('read', 'write')):
                out.append(_finding('VULNERABLE', 'HIGH', 'SMB Unauthenticated Share Access',
                    f'smbmap found accessible shares:\n{stdout[:500]}',
                    target, resolved_ip, port, url=f'smb://{host}:{port}'))
            elif any(w in stdout.lower() for w in ('disk', 'ipc', 'print')):
                out.append(_finding('INFO', 'INFO', 'SMB Shares Enumerated',
                    f'smbmap output:\n{stdout[:400]}',
                    target, resolved_ip, port, url=f'smb://{host}:{port}'))

    # AutoRecon: smbclient -L //HOST/ -U guest
    if _bin('smbclient'):
        stdout, _, _ = await _run(['smbclient', '-L', f'//{host}/', '-U', 'guest', '-N'], timeout=15)
        if stdout and 'sharename' in stdout.lower():
            out.append(_finding('INFO', 'INFO', 'SMB Shares Listed as Guest',
                f'smbclient -L output:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'smb://{host}:{port}'))

    # AutoRecon: enum4linux -a HOST (Linux targets)
    if _bin('enum4linux'):
        stdout, _, _ = await _run(['enum4linux', '-a', host], timeout=60)
        if stdout and any(w in stdout.lower() for w in ('user', 'group', 'password')):
            out.append(_finding('INFO', 'INFO', 'SMB/Samba Enumeration',
                f'enum4linux output (truncated):\n{stdout[:600]}',
                target, resolved_ip, port, url=f'smb://{host}:{port}'))
    return out


# ─── SNMP (161) ──────────────────────────────────────────────────────────────

async def check_snmp(host, port, target, resolved_ip):
    out = []
    # AutoRecon: snmpwalk -v 2c -c public HOST
    if _bin('snmpwalk'):
        stdout, _, rc = await _run(['snmpwalk', '-v', '2c', '-c', 'public', host], timeout=20)
        if rc == 0 and stdout and len(stdout) > 100:
            out.append(_finding('VULNERABLE', 'HIGH', 'SNMP Default Community "public" Accepted',
                f'snmpwalk succeeded with community "public":\n{stdout[:500]}',
                target, resolved_ip, port, url=f'snmp://{host}:{port}'))

    # AutoRecon: snmp-check HOST -c public
    if _bin('snmp-check'):
        stdout, _, _ = await _run(['snmp-check', host, '-c', 'public'], timeout=20)
        if stdout and 'system information' in stdout.lower():
            out.append(_finding('INFO', 'INFO', 'SNMP System Information Disclosed',
                f'snmp-check output:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'snmp://{host}:{port}'))
    return out


# ─── LDAP (389 / 636) ────────────────────────────────────────────────────────

async def check_ldap(host, port, target, resolved_ip):
    out = []
    scheme = 'ldaps' if port == 636 else 'ldap'
    # AutoRecon: ldapsearch -x -H ldap://HOST -b "" -s base namingContexts
    if _bin('ldapsearch'):
        stdout, _, rc = await _run(
            ['ldapsearch', '-x', '-H', f'{scheme}://{host}:{port}',
             '-b', '', '-s', 'base', 'namingContexts'],
            timeout=10)
        if rc == 0 and stdout and 'namingcontexts' in stdout.lower():
            out.append(_finding('VULNERABLE', 'HIGH', 'LDAP Anonymous Bind Allowed',
                f'ldapsearch anonymous bind succeeded. Naming contexts:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'{scheme}://{host}:{port}'))
    return out


# ─── MySQL (3306) ────────────────────────────────────────────────────────────

async def check_mysql(host, port, target, resolved_ip):
    out = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        banner = (await asyncio.wait_for(reader.read(256), timeout=3)).decode('utf-8', errors='replace')
        writer.close()
        ver = re.search(r'(\d+\.\d+\.\d+)', banner)
        version = ver.group(1) if ver else 'unknown'
        out.append(_finding('INFO', 'INFO', 'MySQL Service Detected',
            f'MySQL banner version: {version}',
            target, resolved_ip, port, url=f'mysql://{host}:{port}',
            service_version=version))
    except Exception:
        pass

    # AutoRecon: mysql -h HOST -u root --connect-timeout=5 -e 'SELECT version();'
    if _bin('mysql'):
        stdout, _, rc = await _run(
            ['mysql', '-h', host, '-P', str(port), '-u', 'root',
             '--connect-timeout=5', '-e', 'SELECT version();'],
            timeout=10)
        if rc == 0 and stdout:
            out.append(_finding('VULNERABLE', 'CRITICAL', 'MySQL Unauthenticated Root Access',
                f'mysql -u root connected without password. Version: {stdout[:200]}',
                target, resolved_ip, port, url=f'mysql://{host}:{port}'))
    return out


# ─── PostgreSQL (5432) ───────────────────────────────────────────────────────

async def check_postgresql(host, port, target, resolved_ip):
    out = []
    # AutoRecon: psql -h HOST -U postgres -c '\conninfo'
    if _bin('psql'):
        stdout, _, rc = await _run(
            ['psql', '-h', host, '-p', str(port), '-U', 'postgres', '-c', r'\conninfo'],
            timeout=10)
        if rc == 0 and stdout:
            out.append(_finding('VULNERABLE', 'CRITICAL', 'PostgreSQL Unauthenticated Access (postgres)',
                f'psql connected as postgres without password:\n{stdout[:200]}',
                target, resolved_ip, port, url=f'postgresql://{host}:{port}'))
    return out


# ─── Redis (6379) ────────────────────────────────────────────────────────────

async def check_redis(host, port, target, resolved_ip):
    out = []
    # AutoRecon: redis-cli -h HOST INFO / CONFIG GET '*'
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.write(b'INFO server\r\n')
        await writer.drain()
        resp = (await asyncio.wait_for(reader.read(2048), timeout=5)).decode('utf-8', errors='replace')
        writer.close()
        if 'redis_version' in resp.lower():
            ver = re.search(r'redis_version:(\S+)', resp)
            version = ver.group(1) if ver else 'unknown'
            out.append(_finding('VULNERABLE', 'CRITICAL', 'Redis Unauthenticated Access',
                f'Redis INFO succeeded without auth. Version: {version}',
                target, resolved_ip, port, url=f'redis://{host}:{port}',
                service_version=version))

            # CONFIG GET dir
            try:
                r2, w2 = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
                w2.write(b'CONFIG GET dir\r\n')
                await w2.drain()
                conf = (await asyncio.wait_for(r2.read(512), timeout=3)).decode('utf-8', errors='replace')
                w2.close()
                if conf and not conf.startswith('-'):
                    out.append(_finding('VULNERABLE', 'HIGH', 'Redis CONFIG GET Accessible',
                        f'Redis CONFIG GET dir: {conf[:200]}',
                        target, resolved_ip, port, url=f'redis://{host}:{port}'))
            except Exception:
                pass
    except Exception:
        pass
    return out


# ─── MongoDB (27017) ─────────────────────────────────────────────────────────

async def check_mongodb(host, port, target, resolved_ip):
    out = []
    # AutoRecon: mongosh --host HOST --eval 'db.adminCommand({listDatabases:1})'
    for tool in ('mongosh', 'mongo'):
        if not _bin(tool):
            continue
        stdout, _, rc = await _run(
            [tool, '--host', host, '--port', str(port),
             '--eval', 'db.adminCommand({listDatabases:1})', '--quiet'],
            timeout=15)
        if rc == 0 and stdout and 'databases' in stdout.lower():
            out.append(_finding('VULNERABLE', 'CRITICAL', 'MongoDB Unauthenticated Access',
                f'{tool} listDatabases succeeded without auth:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'mongodb://{host}:{port}'))
        break
    return out


# ─── CouchDB (5984) ──────────────────────────────────────────────────────────

async def check_couchdb(host, port, target, resolved_ip):
    out = []
    # AutoRecon: curl http://HOST:5984/ ; curl http://HOST:5984/_all_dbs
    async with httpx.AsyncClient(timeout=8, verify=False) as client:
        try:
            r = await client.get(f'http://{host}:{port}/')
            if r.status_code == 200 and 'couchdb' in r.text.lower():
                ver = re.search(r'"version"\s*:\s*"([^"]+)"', r.text)
                version = ver.group(1) if ver else 'unknown'
                out.append(_finding('VULNERABLE', 'CRITICAL', 'CouchDB Unauthenticated Access',
                    f'CouchDB root endpoint accessible without auth. Version: {version}',
                    target, resolved_ip, port, url=f'http://{host}:{port}/',
                    http_status=r.status_code, service_version=version))

                r2 = await client.get(f'http://{host}:{port}/_all_dbs')
                if r2.status_code == 200:
                    out.append(_finding('VULNERABLE', 'CRITICAL', 'CouchDB _all_dbs Exposed',
                        f'_all_dbs accessible: {r2.text[:300]}',
                        target, resolved_ip, port, url=f'http://{host}:{port}/_all_dbs',
                        http_status=r2.status_code))

                r3 = await client.get(f'http://{host}:{port}/_users/_all_docs')
                if r3.status_code == 200:
                    out.append(_finding('VULNERABLE', 'CRITICAL', 'CouchDB _users Exposed',
                        f'CouchDB _users/_all_docs accessible: {r3.text[:300]}',
                        target, resolved_ip, port, url=f'http://{host}:{port}/_users/_all_docs',
                        http_status=r3.status_code))
        except Exception:
            pass
    return out


# ─── Memcached (11211) ───────────────────────────────────────────────────────

async def check_memcached(host, port, target, resolved_ip):
    out = []
    # AutoRecon: memcstat --servers=HOST
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.write(b'stats\r\n')
        await writer.drain()
        resp = (await asyncio.wait_for(reader.read(2048), timeout=5)).decode('utf-8', errors='replace')
        writer.close()
        if 'stat ' in resp.lower():
            out.append(_finding('VULNERABLE', 'HIGH', 'Memcached Unauthenticated Access',
                f'Memcached stats command succeeded:\n{resp[:400]}',
                target, resolved_ip, port, url=f'memcached://{host}:{port}'))
    except Exception:
        pass
    return out


# ─── Docker API (2375 / 2376) ────────────────────────────────────────────────

async def check_docker(host, port, target, resolved_ip):
    out = []
    # AutoRecon: curl http://HOST:PORT/version ; /containers/json ; /images/json ; /info
    scheme = 'https' if port == 2376 else 'http'
    async with httpx.AsyncClient(timeout=8, verify=False) as client:
        try:
            r = await client.get(f'{scheme}://{host}:{port}/version')
            if r.status_code == 200 and any(w in r.text.lower() for w in ('docker', 'apiversion')):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Docker API Unauthenticated Access',
                    f'Docker /version accessible without auth:\n{r.text[:300]}',
                    target, resolved_ip, port, url=f'{scheme}://{host}:{port}/version',
                    http_status=r.status_code))

                for path, label in (('/containers/json', 'Container Listing'),
                                    ('/images/json', 'Image Listing'),
                                    ('/info', 'System Info')):
                    r2 = await client.get(f'{scheme}://{host}:{port}{path}')
                    if r2.status_code == 200:
                        out.append(_finding('VULNERABLE', 'CRITICAL',
                            f'Docker {label} Exposed',
                            f'Docker {path} accessible: {r2.text[:300]}',
                            target, resolved_ip, port,
                            url=f'{scheme}://{host}:{port}{path}',
                            http_status=r2.status_code))
        except Exception:
            pass
    return out


# ─── Kubernetes (6443 / 10250 / 2379 / 2380) ─────────────────────────────────

async def check_kubernetes(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False) as client:
        # AutoRecon: curl -sk https://HOST:6443/version ; /api/v1/pods ; /api/v1/namespaces
        if port == 6443:
            for path, label, crit in (
                ('/version', 'K8s API Version Disclosure', False),
                ('/api/v1/pods', 'K8s Unauthenticated Pod Listing', True),
                ('/api/v1/namespaces', 'K8s Unauthenticated Namespace Listing', True),
            ):
                try:
                    r = await client.get(f'https://{host}:{port}{path}')
                    if r.status_code == 200:
                        out.append(_finding(
                            'VULNERABLE', 'CRITICAL' if crit else 'HIGH', label,
                            f'K8s {path} accessible without auth: {r.text[:300]}',
                            target, resolved_ip, port,
                            url=f'https://{host}:{port}{path}',
                            http_status=r.status_code))
                except Exception:
                    pass

        # AutoRecon: curl -sk http://HOST:10250/pods (Kubelet read-only)
        if port == 10250:
            for scheme in ('https', 'http'):
                try:
                    r = await client.get(f'{scheme}://{host}:{port}/pods')
                    if r.status_code == 200:
                        out.append(_finding('VULNERABLE', 'CRITICAL', 'Kubelet API Unauthenticated /pods',
                            f'Kubelet /pods accessible without auth.',
                            target, resolved_ip, port,
                            url=f'{scheme}://{host}:{port}/pods',
                            http_status=r.status_code))
                    break
                except Exception:
                    continue

        # AutoRecon: etcdctl --endpoints=http://HOST:PORT member list ; get /registry/secrets/
        if port in (2379, 2380):
            if _bin('etcdctl'):
                stdout, _, rc = await _run(
                    ['etcdctl', '--endpoints', f'http://{host}:{port}', 'member', 'list'],
                    timeout=10)
                if rc == 0 and stdout:
                    out.append(_finding('VULNERABLE', 'CRITICAL', 'etcd Unauthenticated Access',
                        f'etcd member list succeeded:\n{stdout[:300]}',
                        target, resolved_ip, port, url=f'http://{host}:{port}'))

                    stdout2, _, rc2 = await _run(
                        ['etcdctl', '--endpoints', f'http://{host}:{port}',
                         'get', '/registry/secrets/', '--prefix'],
                        timeout=10)
                    if rc2 == 0 and stdout2:
                        out.append(_finding('VULNERABLE', 'CRITICAL', 'etcd Kubernetes Secrets Exposed',
                            f'etcd get /registry/secrets/ succeeded — K8s secrets readable.',
                            target, resolved_ip, port, url=f'http://{host}:{port}'))
    return out


# ─── Jenkins (8080) ──────────────────────────────────────────────────────────

async def check_jenkins(host, port, target, resolved_ip):
    out = []
    # AutoRecon: curl HOST:PORT/api/json ; /asynchPeople/api/json ; /script ; /credentials/
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/api/json?pretty=true')
            if r.status_code == 200 and any(w in r.text.lower() for w in ('_class', 'jenkins', 'jobs')):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Jenkins API Unauthenticated Access',
                    f'Jenkins /api/json accessible without auth:\n{r.text[:300]}',
                    target, resolved_ip, port, url=f'http://{host}:{port}/api/json',
                    http_status=r.status_code))

            r2 = await client.get(f'http://{host}:{port}/script')
            if r2.status_code == 200 and 'groovy' in r2.text.lower():
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Jenkins Script Console Exposed',
                    'Jenkins Groovy script console accessible without auth — RCE possible.',
                    target, resolved_ip, port, url=f'http://{host}:{port}/script',
                    http_status=r2.status_code))

            r3 = await client.get(f'http://{host}:{port}/asynchPeople/api/json')
            if r3.status_code == 200:
                out.append(_finding('VULNERABLE', 'MEDIUM', 'Jenkins User Enumeration',
                    f'Jenkins /asynchPeople/api/json accessible:\n{r3.text[:200]}',
                    target, resolved_ip, port, url=f'http://{host}:{port}/asynchPeople/api/json',
                    http_status=r3.status_code))
        except Exception:
            pass
    return out


# ─── Jolokia JMX (8778) ──────────────────────────────────────────────────────

async def check_jolokia(host, port, target, resolved_ip):
    out = []
    # AutoRecon: curl HOST:PORT/jolokia/ ; /jolokia/list ; /jolokia/read/java.lang:type=Runtime/SystemProperties
    async with httpx.AsyncClient(timeout=8, verify=False) as client:
        for base in (f'/jolokia/', f'/actuator/jolokia/'):
            try:
                r = await client.get(f'http://{host}:{port}{base}')
                if r.status_code == 200 and 'jolokia' in r.text.lower():
                    out.append(_finding('VULNERABLE', 'HIGH', 'Jolokia JMX Endpoint Unauthenticated',
                        f'Jolokia at {base} accessible:\n{r.text[:300]}',
                        target, resolved_ip, port,
                        url=f'http://{host}:{port}{base}',
                        http_status=r.status_code))

                    r2 = await client.get(f'http://{host}:{port}{base}list')
                    if r2.status_code == 200:
                        out.append(_finding('VULNERABLE', 'HIGH', 'Jolokia MBean List Exposed',
                            f'Jolokia /list MBeans accessible:\n{r2.text[:200]}',
                            target, resolved_ip, port,
                            url=f'http://{host}:{port}{base}list',
                            http_status=r2.status_code))

                    r3 = await client.get(
                        f'http://{host}:{port}{base}read/java.lang:type=Runtime/SystemProperties')
                    if r3.status_code == 200:
                        out.append(_finding('VULNERABLE', 'HIGH', 'Jolokia JVM System Properties Exposed',
                            f'Java SystemProperties readable via Jolokia.',
                            target, resolved_ip, port,
                            url=f'http://{host}:{port}{base}read/java.lang:type=Runtime/SystemProperties',
                            http_status=r3.status_code))
                    break
            except Exception:
                continue
    return out


# ─── AJP / Ghostcat (8009) ───────────────────────────────────────────────────

async def check_ajp(host, port, target, resolved_ip):
    out = []
    # Probe AJP13 via TCP magic bytes — if it responds the port is live
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.write(b'\x12\x34\x00\x01\x0a')
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(64), timeout=3)
        writer.close()
        if resp and len(resp) > 2:
            out.append(_finding('VULNERABLE', 'HIGH', 'AJP Connector Exposed (CVE-2020-1938 Ghostcat)',
                f'AJP13 port {port} responding — potential Ghostcat (file read/inclusion) risk.',
                target, resolved_ip, port, url=f'ajp://{host}:{port}'))
    except Exception:
        pass
    return out


# ─── WinRM (5985 / 5986) ─────────────────────────────────────────────────────

async def check_winrm(host, port, target, resolved_ip):
    out = []
    scheme = 'https' if port == 5986 else 'http'
    async with httpx.AsyncClient(timeout=8, verify=False) as client:
        try:
            r = await client.get(f'{scheme}://{host}:{port}/wsman')
            if r.status_code in (200, 401, 403):
                status = 'VULNERABLE' if r.status_code == 200 else 'INFO'
                out.append(_finding(status, 'HIGH' if status == 'VULNERABLE' else 'INFO',
                    'WinRM Service Detected',
                    f'WinRM /wsman responded HTTP {r.status_code}.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/wsman',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── VNC (5900 / 5901) ───────────────────────────────────────────────────────

async def check_vnc(host, port, target, resolved_ip):
    out = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        banner = (await asyncio.wait_for(reader.read(64), timeout=3)).decode('utf-8', errors='replace').strip()
        writer.close()
        if 'rfb' in banner.lower():
            out.append(_finding('INFO', 'MEDIUM', 'VNC Service Detected',
                f'VNC RFB banner: {banner[:100]}',
                target, resolved_ip, port, url=f'vnc://{host}:{port}'))
    except Exception:
        pass
    return out


# ─── NFS (2049) ──────────────────────────────────────────────────────────────

async def check_nfs(host, port, target, resolved_ip):
    out = []
    # AutoRecon: showmount -e HOST
    if _bin('showmount'):
        stdout, _, rc = await _run(['showmount', '-e', host], timeout=15)
        if rc == 0 and stdout and '/' in stdout:
            out.append(_finding('VULNERABLE', 'HIGH', 'NFS Exports Exposed',
                f'showmount -e output:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'nfs://{host}:{port}'))
    return out


# ─── Rsync (873) ─────────────────────────────────────────────────────────────

async def check_rsync(host, port, target, resolved_ip):
    out = []
    # AutoRecon: rsync --list-only rsync://HOST/
    if _bin('rsync'):
        stdout, _, rc = await _run(['rsync', '--list-only', f'rsync://{host}/'], timeout=15)
        if rc == 0 and stdout:
            out.append(_finding('VULNERABLE', 'HIGH', 'Rsync Unauthenticated Module Listing',
                f'rsync --list-only output:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'rsync://{host}:{port}'))
    return out


# ─── Cassandra (9042 / 9160) ─────────────────────────────────────────────────

async def check_cassandra(host, port, target, resolved_ip):
    out = []
    # AutoRecon: cqlsh HOST PORT -e 'DESCRIBE KEYSPACES;'
    if _bin('cqlsh'):
        stdout, _, rc = await _run(['cqlsh', host, str(port), '-e', 'DESCRIBE KEYSPACES;'], timeout=15)
        if rc == 0 and stdout:
            out.append(_finding('VULNERABLE', 'CRITICAL', 'Cassandra Unauthenticated Access',
                f'cqlsh DESCRIBE KEYSPACES succeeded without auth:\n{stdout[:300]}',
                target, resolved_ip, port, url=f'cassandra://{host}:{port}'))
    return out


# ─── VMware ESXi (902) ───────────────────────────────────────────────────────

async def check_vmware(host, port, target, resolved_ip):
    out = []
    # AutoRecon: curl -skL https://HOST/ui ; /host ; /sdk/vimServiceVersions.xml
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        for path in ('/ui', '/host', '/sdk/vimServiceVersions.xml'):
            try:
                r = await client.get(f'https://{host}:{port}{path}')
                if r.status_code in (200, 301, 302) and any(
                    m in r.text.lower() for m in ('vmware', 'esxi', 'vsphere', 'vimservice')
                ):
                    out.append(_finding('INFO', 'MEDIUM', 'VMware ESXi/vSphere Interface Exposed',
                        f'VMware service at {path} (HTTP {r.status_code}).',
                        target, resolved_ip, port,
                        url=f'https://{host}:{port}{path}',
                        http_status=r.status_code))
                    break
            except Exception:
                continue
    return out


# ─── MSSQL (1433) ────────────────────────────────────────────────────────────

async def check_mssql(host, port, target, resolved_ip):
    out = []
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.close()
        out.append(_finding('INFO', 'INFO', 'MSSQL Service Detected',
            f'MSSQL port {port} is open on {host}.',
            target, resolved_ip, port, url=f'mssql://{host}:{port}'))
    except Exception:
        pass

    # AutoRecon: impacket-mssqlclient HOST -windows-auth
    for tool in ('impacket-mssqlclient', 'mssqlclient.py'):
        if _bin(tool):
            stdout, _, rc = await _run([_bin(tool), host, '-windows-auth'], timeout=15)
            if stdout and rc == 0:
                out.append(_finding('POTENTIAL', 'HIGH', 'MSSQL Login Response',
                    f'impacket-mssqlclient output:\n{stdout[:300]}',
                    target, resolved_ip, port, url=f'mssql://{host}:{port}'))
            break
    return out


# ─── Oracle (1521) ───────────────────────────────────────────────────────────

async def check_oracle(host, port, target, resolved_ip):
    out = []
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.close()
        out.append(_finding('INFO', 'INFO', 'Oracle TNS Listener Detected',
            f'Oracle TNS listener port {port} is open on {host}.',
            target, resolved_ip, port, url=f'oracle://{host}:{port}'))
    except Exception:
        pass

    # AutoRecon: tnscmd10g version -h HOST
    if _bin('tnscmd10g'):
        stdout, _, rc = await _run(['tnscmd10g', 'version', '-h', host], timeout=10)
        if rc == 0 and stdout:
            out.append(_finding('INFO', 'INFO', 'Oracle TNS Version Disclosed',
                f'tnscmd10g version:\n{stdout[:300]}',
                target, resolved_ip, port, url=f'oracle://{host}:{port}'))
    return out


# ─── RDP (3389) ──────────────────────────────────────────────────────────────

async def check_rdp(host, port, target, resolved_ip):
    out = []
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.close()
        out.append(_finding('INFO', 'INFO', 'RDP Service Detected',
            f'RDP port {port} is open on {host}.',
            target, resolved_ip, port, url=f'rdp://{host}:{port}'))
    except Exception:
        pass

    # AutoRecon: rdp-sec-check HOST
    if _bin('rdp-sec-check'):
        stdout, _, _ = await _run(['rdp-sec-check', host], timeout=20)
        if stdout and any(w in stdout.lower() for w in ('ssl', 'tls', 'nla', 'weak', 'issue')):
            out.append(_finding('POTENTIAL', 'MEDIUM', 'RDP Security Configuration Issues',
                f'rdp-sec-check findings:\n{stdout[:400]}',
                target, resolved_ip, port, url=f'rdp://{host}:{port}'))
    return out


# ─── ActiveMQ / AMQP (5671 / 5672 / 61616) ───────────────────────────────────

async def check_activemq(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False) as client:
        # AutoRecon: curl -u admin:admin .../api/message/TEST?type=queue (default creds)
        try:
            r = await client.post(
                f'http://{host}:{port}/api/message/TEST?type=queue',
                data={'body': 'vaktscan-probe'},
                auth=('admin', 'admin'))
            if r.status_code in (200, 201):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'ActiveMQ Default Credentials (admin:admin)',
                    f'ActiveMQ API accessible with admin:admin.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/message/TEST',
                    http_status=r.status_code))
        except Exception:
            pass

        try:
            r2 = await client.get(f'http://{host}:{port}/')
            if r2.status_code in (200, 401):
                out.append(_finding('INFO', 'INFO', 'AMQP/ActiveMQ Service Detected',
                    f'AMQP/ActiveMQ on port {port} responded HTTP {r2.status_code}.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/',
                    http_status=r2.status_code))
        except Exception:
            pass
    return out


# ─── Dispatch ────────────────────────────────────────────────────────────────

PORT_DISPATCH = {
    21:    check_ftp,
    22:    check_ssh,
    25:    check_smtp,
    53:    check_dns,
    88:    check_kerberos,
    111:   check_rpc,
    123:   check_ntp,
    135:   check_rpc,
    139:   check_smb,
    161:   check_snmp,
    389:   check_ldap,
    445:   check_smb,
    465:   check_smtp,
    587:   check_smtp,
    593:   check_rpc,
    636:   check_ldap,
    873:   check_rsync,
    902:   check_vmware,
    1433:  check_mssql,
    1521:  check_oracle,
    2049:  check_nfs,
    2375:  check_docker,
    2376:  check_docker,
    2379:  check_kubernetes,
    2380:  check_kubernetes,
    3306:  check_mysql,
    3389:  check_rdp,
    5432:  check_postgresql,
    5671:  check_activemq,
    5672:  check_activemq,
    5900:  check_vnc,
    5901:  check_vnc,
    5984:  check_couchdb,
    6379:  check_redis,
    6443:  check_kubernetes,
    8009:  check_ajp,
    8778:  check_jolokia,
    9042:  check_cassandra,
    9160:  check_cassandra,
    10250: check_kubernetes,
    11211: check_memcached,
    27017: check_mongodb,
    61616: check_activemq,
}


async def run_scans(target_obj, port, **_kwargs):
    scan_address = target_obj['scan_address']
    resolved_ip  = target_obj.get('resolved_ip', scan_address)
    display      = target_obj.get('display_target', scan_address)

    check_fn = PORT_DISPATCH.get(port)
    if check_fn is None:
        return []

    try:
        findings = await check_fn(scan_address, port, display, resolved_ip)
    except Exception as e:
        print(f"  [!] service_recon error on {scan_address}:{port} — {e}")
        return []

    for f in findings:
        f['module'] = MODULE_NAME

    return findings
