"""
VaktScan Service Recon Module
Port-specific recon and vulnerability checks drawn directly from AutoRecon methodology.
Each check mirrors the exact tool invocations from AutoRecon.sh — tested logic, same tools.

Covers: FTP, SSH, SMTP, DNS, Kerberos, RPC, NTP, SMB, SNMP, LDAP, MySQL, PostgreSQL,
        Redis, MongoDB, CouchDB, Memcached, Docker API, Kubernetes, Jenkins,
        Jolokia, AJP (Ghostcat), WinRM, VNC, NFS, Rsync, ActiveMQ/AMQP,
        Cassandra, VMware ESXi, MSSQL, Oracle, RDP,
        Spring Boot Actuator, Jupyter Notebook, Hadoop YARN, Hadoop HDFS NameNode,
        ZooKeeper, Kafka, HashiCorp Consul, HashiCorp Vault, MinIO, Apache Solr,
        Apache Tomcat, WebLogic, JBoss/WildFly, GlassFish, Alertmanager, Loki,
        Jaeger, Zipkin, Splunk, Traefik, Portainer, RabbitMQ Management, IPMI,
        Nexus Repository, Artifactory, TeamCity, SonarQube, Istio/Envoy admin.
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


# ─── Spring Boot Actuator (8080 / 8081 / 8443 / 8090) ───────────────────────

async def check_spring_actuator(host, port, target, resolved_ip):
    out = []
    scheme = 'https' if port == 8443 else 'http'
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # Probe /actuator/health first to confirm it's a Spring Boot app
        try:
            r = await client.get(f'{scheme}://{host}:{port}/actuator/health')
            if r.status_code != 200:
                return out
            out.append(_finding('INFO', 'INFO', 'Spring Boot Actuator Detected',
                f'Spring Boot /actuator/health accessible (HTTP {r.status_code}).',
                target, resolved_ip, port,
                url=f'{scheme}://{host}:{port}/actuator/health',
                http_status=r.status_code))
        except Exception:
            return out

        # /actuator/env — contains environment variables, secrets, passwords
        try:
            r = await client.get(f'{scheme}://{host}:{port}/actuator/env')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Spring Boot Actuator /env Exposed',
                    'Spring Boot /actuator/env accessible without auth — '
                    'may expose passwords, API keys, and environment secrets.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/actuator/env',
                    http_status=r.status_code))
        except Exception:
            pass

        # /actuator/heapdump — binary heap dump that contains credentials in memory
        try:
            r = await client.get(f'{scheme}://{host}:{port}/actuator/heapdump')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Spring Boot Actuator /heapdump Exposed',
                    'Spring Boot /actuator/heapdump accessible without auth — '
                    'heap dump download possible, may contain plaintext credentials.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/actuator/heapdump',
                    http_status=r.status_code))
        except Exception:
            pass

        for path, label, severity in (
            ('/actuator/mappings', 'Spring Boot Actuator /mappings Exposed', 'HIGH'),
            ('/actuator/logfile',  'Spring Boot Actuator /logfile Exposed',  'HIGH'),
            ('/actuator/beans',    'Spring Boot Actuator /beans Exposed',    'MEDIUM'),
        ):
            try:
                r = await client.get(f'{scheme}://{host}:{port}{path}')
                if r.status_code == 200:
                    out.append(_finding('VULNERABLE', severity, label,
                        f'Spring Boot {path} accessible without auth (HTTP {r.status_code}).',
                        target, resolved_ip, port,
                        url=f'{scheme}://{host}:{port}{path}',
                        http_status=r.status_code))
            except Exception:
                pass
    return out


# ─── Jupyter Notebook (8888 / 8889) ──────────────────────────────────────────

async def check_jupyter(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /api/kernels — unauthenticated access means direct RCE
        try:
            r = await client.get(f'http://{host}:{port}/api/kernels')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Jupyter Notebook /api/kernels Unauthenticated',
                    'Jupyter /api/kernels accessible without auth — '
                    'kernel management possible, leading to direct RCE.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/kernels',
                    http_status=r.status_code))
        except Exception:
            pass

        # /api/contents — filesystem browsing without auth
        try:
            r = await client.get(f'http://{host}:{port}/api/contents')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Jupyter Notebook /api/contents Unauthenticated',
                    'Jupyter /api/contents accessible without auth — '
                    'full filesystem read/write possible.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/contents',
                    http_status=r.status_code))
        except Exception:
            pass

        # /tree — notebook browser UI
        try:
            r = await client.get(f'http://{host}:{port}/tree')
            if r.status_code == 200 and any(w in r.text.lower() for w in ('jupyter', 'notebook', 'tree')):
                out.append(_finding('INFO', 'INFO', 'Jupyter Notebook /tree Accessible',
                    'Jupyter Notebook UI at /tree is accessible.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/tree',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Hadoop YARN (8088) ───────────────────────────────────────────────────────

async def check_hadoop_yarn(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/ws/v1/cluster/info')
            if r.status_code == 200 and any(w in r.text.lower() for w in ('hadoop', 'yarn', 'clusterinfo')):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Hadoop YARN ResourceManager Unauthenticated',
                    'Hadoop YARN /ws/v1/cluster/info accessible without auth — '
                    'unauthenticated app submission leads to RCE.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/ws/v1/cluster/info',
                    http_status=r.status_code))

                r2 = await client.get(f'http://{host}:{port}/ws/v1/cluster/apps')
                if r2.status_code == 200:
                    out.append(_finding('VULNERABLE', 'CRITICAL', 'Hadoop YARN Application List Exposed',
                        'Hadoop YARN /ws/v1/cluster/apps accessible — '
                        'full application listing and submission API exposed.',
                        target, resolved_ip, port,
                        url=f'http://{host}:{port}/ws/v1/cluster/apps',
                        http_status=r2.status_code))
        except Exception:
            pass
    return out


# ─── Hadoop HDFS NameNode (50070 / 9870) ─────────────────────────────────────

async def check_hadoop_hdfs(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/jmx?qry=Hadoop:*')
            if r.status_code == 200 and 'hadoop' in r.text.lower():
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Hadoop HDFS NameNode JMX Exposed',
                    'Hadoop HDFS /jmx?qry=Hadoop:* accessible without auth — '
                    'cluster metadata and configuration exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/jmx?qry=Hadoop:*',
                    http_status=r.status_code))
        except Exception:
            pass

        try:
            r = await client.get(f'http://{host}:{port}/listPaths/')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Hadoop HDFS /listPaths Exposed',
                    'Hadoop HDFS /listPaths/ accessible without auth — filesystem listing possible.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/listPaths/',
                    http_status=r.status_code))
        except Exception:
            pass

        try:
            r = await client.get(f'http://{host}:{port}/logs/')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Hadoop HDFS /logs Exposed',
                    'Hadoop HDFS /logs/ accessible without auth — log files may contain credentials.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/logs/',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── ZooKeeper (2181) ────────────────────────────────────────────────────────

async def check_zookeeper(host, port, target, resolved_ip):
    out = []
    for cmd, label in (
        (b'ruok\n', 'ruok'),
        (b'stat\n', 'stat'),
        (b'dump\n', 'dump'),
    ):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            writer.write(cmd)
            await writer.drain()
            resp = (await asyncio.wait_for(reader.read(4096), timeout=3)).decode('utf-8', errors='replace')
            writer.close()
            if resp and ('imok' in resp or len(resp) > 10):
                out.append(_finding('VULNERABLE', 'HIGH', f'ZooKeeper Unauthenticated Access ({label})',
                    f'ZooKeeper responded to {label.upper()} command:\n{resp[:300]}',
                    target, resolved_ip, port,
                    url=f'zookeeper://{host}:{port}'))
                break
        except Exception:
            pass
    return out


# ─── Kafka (9092) ────────────────────────────────────────────────────────────

async def check_kafka(host, port, target, resolved_ip):
    out = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        banner = (await asyncio.wait_for(reader.read(256), timeout=3)).decode('utf-8', errors='replace')
        writer.close()
        out.append(_finding('INFO', 'INFO', 'Kafka Broker Port Responding',
            f'Kafka port {port} on {host} is accepting connections. Banner: {banner[:100]}',
            target, resolved_ip, port,
            url=f'kafka://{host}:{port}'))
    except Exception:
        pass
    return out


# ─── HashiCorp Consul (8500 / 8501) ──────────────────────────────────────────

async def check_consul(host, port, target, resolved_ip):
    out = []
    scheme = 'https' if port == 8501 else 'http'
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /v1/agent/self — full agent configuration, tokens, datacenter info
        try:
            r = await client.get(f'{scheme}://{host}:{port}/v1/agent/self')
            if r.status_code == 200 and any(w in r.text.lower() for w in ('config', 'datacenter', 'consul')):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'HashiCorp Consul Agent API Unauthenticated',
                    'Consul /v1/agent/self accessible without ACL token — '
                    'full agent config including tokens may be exposed.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/v1/agent/self',
                    http_status=r.status_code))
        except Exception:
            pass

        # /v1/kv/?keys — KV store key listing
        try:
            r = await client.get(f'{scheme}://{host}:{port}/v1/kv/?keys')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'HashiCorp Consul KV Store Readable',
                    'Consul /v1/kv/?keys accessible without ACL token — '
                    'KV store key listing possible, may contain secrets.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/v1/kv/?keys',
                    http_status=r.status_code))
        except Exception:
            pass

        # /v1/catalog/services — service registry listing
        try:
            r = await client.get(f'{scheme}://{host}:{port}/v1/catalog/services')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'HashiCorp Consul Service Catalog Exposed',
                    'Consul /v1/catalog/services accessible without ACL token — '
                    'full service registry exposed.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/v1/catalog/services',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── HashiCorp Vault (8200) ───────────────────────────────────────────────────

async def check_vault(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /v1/sys/health — initialization and seal status
        try:
            r = await client.get(f'http://{host}:{port}/v1/sys/health')
            if r.status_code in (200, 429, 472, 473, 501, 503):
                initialized = '"initialized":true' in r.text.lower().replace(' ', '')
                unsealed = '"sealed":false' in r.text.lower().replace(' ', '')
                detail = f'Vault health responded HTTP {r.status_code}. '
                if initialized and unsealed:
                    detail += 'Vault is INITIALIZED and UNSEALED.'
                out.append(_finding('INFO', 'INFO', 'HashiCorp Vault Detected',
                    detail + f'\n{r.text[:200]}',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/v1/sys/health',
                    http_status=r.status_code))
        except Exception:
            return out

        # /v1/sys/seal-status
        try:
            r = await client.get(f'http://{host}:{port}/v1/sys/seal-status')
            if r.status_code == 200:
                out.append(_finding('INFO', 'INFO', 'HashiCorp Vault Seal Status Accessible',
                    f'Vault /v1/sys/seal-status accessible: {r.text[:200]}',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/v1/sys/seal-status',
                    http_status=r.status_code))
        except Exception:
            pass

        # /v1/sys/mounts — lists secret engines; should require auth
        try:
            r = await client.get(f'http://{host}:{port}/v1/sys/mounts')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'HashiCorp Vault /sys/mounts Unauthenticated',
                    'Vault /v1/sys/mounts accessible without token — '
                    'secret engine listing possible without authentication.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/v1/sys/mounts',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── MinIO (9000 / 9001) ─────────────────────────────────────────────────────

async def check_minio(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # Check for MinIO at root
        try:
            r = await client.get(f'http://{host}:{port}/')
            if r.status_code in (200, 403) and any(
                w in r.text.lower() for w in ('minio', 'listbuckets', 'buckets', 'xmlbody')
            ):
                out.append(_finding('INFO', 'INFO', 'MinIO Object Storage Detected',
                    f'MinIO detected at http://{host}:{port}/ (HTTP {r.status_code}).',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/',
                    http_status=r.status_code))
        except Exception:
            pass

        # Try default credentials minioadmin:minioadmin
        try:
            r = await client.get(
                f'http://{host}:{port}/minio/health/live',
                auth=('minioadmin', 'minioadmin'))
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'MinIO Default Credentials (minioadmin:minioadmin)',
                    'MinIO /minio/health/live accessible with default credentials minioadmin:minioadmin.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/minio/health/live',
                    http_status=r.status_code))
                return out
        except Exception:
            pass

        # Try login endpoint
        try:
            r = await client.post(
                f'http://{host}:{port}/minio/login',
                data={'username': 'minioadmin', 'password': 'minioadmin'})
            if r.status_code in (200, 303):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'MinIO Default Credentials (minioadmin:minioadmin)',
                    'MinIO login succeeded with default credentials minioadmin:minioadmin.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/minio/login',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Apache Solr (8983) ───────────────────────────────────────────────────────

async def check_solr(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /solr/admin/cores?action=STATUS — core listing
        try:
            r = await client.get(f'http://{host}:{port}/solr/admin/cores?action=STATUS')
            if r.status_code == 200 and any(w in r.text.lower() for w in ('status', 'solr', 'core')):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Apache Solr Admin Cores Exposed',
                    'Solr /solr/admin/cores?action=STATUS accessible without auth — '
                    'all core names and configuration exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/solr/admin/cores?action=STATUS',
                    http_status=r.status_code))
        except Exception:
            pass

        # /solr/admin/info/system — version disclosure
        try:
            r = await client.get(f'http://{host}:{port}/solr/admin/info/system')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Apache Solr System Info Exposed',
                    'Solr /solr/admin/info/system accessible — version and JVM info disclosed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/solr/admin/info/system',
                    http_status=r.status_code))
        except Exception:
            pass

        # /solr/#/ — admin UI
        try:
            r = await client.get(f'http://{host}:{port}/solr/#/')
            if r.status_code == 200 and 'solr' in r.text.lower():
                out.append(_finding('INFO', 'INFO', 'Apache Solr Admin UI Accessible',
                    'Solr admin UI at /solr/#/ is accessible.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/solr/#/',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Apache Tomcat (8080 / 8443) ─────────────────────────────────────────────

async def check_tomcat(host, port, target, resolved_ip):
    out = []
    scheme = 'https' if port == 8443 else 'http'
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /manager/html — unauthenticated access
        try:
            r = await client.get(f'{scheme}://{host}:{port}/manager/html')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('tomcat', 'manager', 'application manager')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Apache Tomcat Manager Unauthenticated',
                    'Tomcat /manager/html accessible without credentials — WAR deployment possible.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/manager/html',
                    http_status=r.status_code))
                return out
        except Exception:
            pass

        # Try default creds tomcat:tomcat and admin:admin
        for user, passwd in (('tomcat', 'tomcat'), ('admin', 'admin'), ('admin', 's3cret')):
            try:
                r = await client.get(
                    f'{scheme}://{host}:{port}/manager/html',
                    auth=(user, passwd))
                if r.status_code == 200 and any(
                    w in r.text.lower() for w in ('tomcat', 'manager')
                ):
                    out.append(_finding('VULNERABLE', 'CRITICAL',
                        f'Apache Tomcat Manager Default Credentials ({user}:{passwd})',
                        f'Tomcat /manager/html accessible with {user}:{passwd} — WAR deployment possible.',
                        target, resolved_ip, port,
                        url=f'{scheme}://{host}:{port}/manager/html',
                        http_status=r.status_code))
                    return out
            except Exception:
                pass

        # /host-manager/html
        try:
            r = await client.get(f'{scheme}://{host}:{port}/host-manager/html')
            if r.status_code == 200 and 'tomcat' in r.text.lower():
                out.append(_finding('VULNERABLE', 'HIGH', 'Apache Tomcat Host Manager Accessible',
                    'Tomcat /host-manager/html accessible without auth.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/host-manager/html',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── WebLogic (7001 / 7002) ───────────────────────────────────────────────────

async def check_weblogic(host, port, target, resolved_ip):
    out = []
    scheme = 'https' if port == 7002 else 'http'
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /console — admin console
        try:
            r = await client.get(f'{scheme}://{host}:{port}/console')
            if r.status_code in (200, 301, 302) and any(
                w in r.text.lower() for w in ('weblogic', 'oracle', 'console')
            ):
                out.append(_finding('INFO', 'INFO', 'WebLogic Admin Console Detected',
                    f'WebLogic /console accessible (HTTP {r.status_code}).',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/console',
                    http_status=r.status_code))
        except Exception:
            pass

        # CVE-2020-14882 — authentication bypass via URL encoding
        try:
            r = await client.get(
                f'{scheme}://{host}:{port}/console/css/%252E%252E%252Fconsole.portal')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('welcome', 'weblogic', 'oracle')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL',
                    'WebLogic CVE-2020-14882 Authentication Bypass',
                    'WebLogic Console auth bypass via %252E%252E%252F path traversal succeeded — '
                    'CVE-2020-14882.',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/console/css/%252E%252E%252Fconsole.portal',
                    payload_url=f'{scheme}://{host}:{port}/console/css/%252E%252E%252Fconsole.portal',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── JBoss / WildFly (9990) ───────────────────────────────────────────────────

async def check_jboss(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /management — REST management API
        try:
            r = await client.get(f'http://{host}:{port}/management')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('wildfly', 'jboss', 'management', 'server-state')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'JBoss/WildFly Management API Unauthenticated',
                    'JBoss /management API accessible without credentials — '
                    'full server management including deployment is exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/management',
                    http_status=r.status_code))
                return out
        except Exception:
            pass

        # Try empty credentials on /management
        try:
            r = await client.get(f'http://{host}:{port}/management', auth=('', ''))
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('wildfly', 'jboss', 'management')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'JBoss/WildFly Management API Empty Credentials',
                    'JBoss /management accessible with empty credentials.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/management',
                    http_status=r.status_code))
                return out
        except Exception:
            pass

        # /console — web admin console
        try:
            r = await client.get(f'http://{host}:{port}/console')
            if r.status_code in (200, 301, 302) and any(
                w in r.text.lower() for w in ('wildfly', 'jboss', 'console')
            ):
                out.append(_finding('INFO', 'INFO', 'JBoss/WildFly Admin Console Accessible',
                    f'JBoss/WildFly /console accessible (HTTP {r.status_code}).',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/console',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── GlassFish (4848) ────────────────────────────────────────────────────────

async def check_glassfish(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /management/domain — REST management API
        try:
            r = await client.get(f'https://{host}:{port}/management/domain')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('glassfish', 'domain', 'resources')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'GlassFish Management API Unauthenticated',
                    'GlassFish /management/domain accessible without credentials.',
                    target, resolved_ip, port,
                    url=f'https://{host}:{port}/management/domain',
                    http_status=r.status_code))
                return out
        except Exception:
            pass

        # Try admin with empty password
        try:
            r = await client.get(
                f'https://{host}:{port}/management/domain',
                auth=('admin', ''))
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'GlassFish Default Empty Admin Password',
                    'GlassFish /management/domain accessible with admin:(empty password).',
                    target, resolved_ip, port,
                    url=f'https://{host}:{port}/management/domain',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Alertmanager (9093) ─────────────────────────────────────────────────────

async def check_alertmanager(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/-/status')
            if r.status_code == 200:
                out.append(_finding('INFO', 'INFO', 'Alertmanager Status Endpoint Accessible',
                    f'Alertmanager /-/status accessible (HTTP {r.status_code}).',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/-/status',
                    http_status=r.status_code))
        except Exception:
            pass

        try:
            r = await client.get(f'http://{host}:{port}/api/v2/alerts')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Alertmanager API /alerts Unauthenticated',
                    'Alertmanager /api/v2/alerts accessible without auth — '
                    'active alerts can be read and silenced.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/v2/alerts',
                    http_status=r.status_code))
        except Exception:
            pass

        try:
            r = await client.get(f'http://{host}:{port}/api/v2/receivers')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Alertmanager API /receivers Unauthenticated',
                    'Alertmanager /api/v2/receivers accessible without auth — '
                    'notification receiver configuration exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/v2/receivers',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Loki (3100) ─────────────────────────────────────────────────────────────

async def check_loki(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/ready')
            if r.status_code == 200:
                out.append(_finding('INFO', 'INFO', 'Loki Log Aggregation Service Detected',
                    f'Loki /ready endpoint accessible (HTTP {r.status_code}).',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/ready',
                    http_status=r.status_code))
        except Exception:
            return out

        try:
            r = await client.get(
                f'http://{host}:{port}/loki/api/v1/query'
                f'?query=%7Bjob%3D%22%22%7D')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Loki Unauthenticated Log Query',
                    'Loki /loki/api/v1/query accessible without auth — '
                    'arbitrary log queries possible.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/loki/api/v1/query?query=%7Bjob%3D%22%22%7D',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Jaeger (16686) ──────────────────────────────────────────────────────────

async def check_jaeger(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/api/services')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Jaeger API /services Unauthenticated',
                    'Jaeger /api/services accessible without auth — '
                    'full service list from distributed tracing exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/services',
                    http_status=r.status_code))
        except Exception:
            pass

        try:
            r = await client.get(f'http://{host}:{port}/api/traces?service=vaktscan-probe')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Jaeger API /traces Unauthenticated',
                    'Jaeger /api/traces accessible without auth — '
                    'distributed trace data exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/traces?service=vaktscan-probe',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Zipkin (9411) ───────────────────────────────────────────────────────────

async def check_zipkin(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/api/v2/services')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Zipkin API /services Unauthenticated',
                    'Zipkin /api/v2/services accessible without auth — '
                    'service topology from distributed tracing exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/v2/services',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Splunk (8000 / 8089) ────────────────────────────────────────────────────

async def check_splunk(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # Detect Splunk web UI on 8000
        if port == 8000:
            try:
                r = await client.get(f'http://{host}:{port}/en-US/account/login')
                if r.status_code == 200 and 'splunk' in r.text.lower():
                    out.append(_finding('INFO', 'INFO', 'Splunk Web UI Detected',
                        f'Splunk login page accessible at http://{host}:{port}/en-US/account/login.',
                        target, resolved_ip, port,
                        url=f'http://{host}:{port}/en-US/account/login',
                        http_status=r.status_code))
            except Exception:
                pass

        # REST API on 8089 — try default admin:changeme
        if port == 8089:
            try:
                r = await client.post(
                    f'https://{host}:{port}/services/auth/login',
                    data={'username': 'admin', 'password': 'changeme'})
                if r.status_code == 200 and 'sessionkey' in r.text.lower():
                    out.append(_finding('VULNERABLE', 'CRITICAL',
                        'Splunk Default Credentials (admin:changeme)',
                        'Splunk REST API /services/auth/login succeeded with admin:changeme — '
                        'full Splunk management access.',
                        target, resolved_ip, port,
                        url=f'https://{host}:{port}/services/auth/login',
                        http_status=r.status_code))
            except Exception:
                pass
    return out


# ─── Traefik (8080) ──────────────────────────────────────────────────────────

async def check_traefik(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'http://{host}:{port}/dashboard/')
            if r.status_code == 200 and any(w in r.text.lower() for w in ('traefik', 'dashboard')):
                out.append(_finding('VULNERABLE', 'HIGH', 'Traefik Dashboard Unauthenticated',
                    'Traefik /dashboard/ accessible without auth — '
                    'routing configuration and backend services exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/dashboard/',
                    http_status=r.status_code))
        except Exception:
            pass

        try:
            r = await client.get(f'http://{host}:{port}/api/rawdata')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Traefik /api/rawdata Unauthenticated',
                    'Traefik /api/rawdata accessible without auth — '
                    'full routing table with all backends and middleware exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/rawdata',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Portainer (9000 / 9443) ─────────────────────────────────────────────────

async def check_portainer(host, port, target, resolved_ip):
    out = []
    scheme = 'https' if port == 9443 else 'http'
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f'{scheme}://{host}:{port}/api/status')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('portainer', 'version', 'instanceid')
            ):
                out.append(_finding('INFO', 'INFO', 'Portainer API Detected',
                    f'Portainer /api/status accessible (HTTP {r.status_code}): {r.text[:200]}',
                    target, resolved_ip, port,
                    url=f'{scheme}://{host}:{port}/api/status',
                    http_status=r.status_code))
            else:
                return out
        except Exception:
            return out

        # Try default credentials
        for user, passwd in (('admin', 'admin'), ('admin', 'portainer')):
            try:
                r = await client.post(
                    f'{scheme}://{host}:{port}/api/auth',
                    json={'username': user, 'password': passwd})
                if r.status_code == 200 and 'jwt' in r.text.lower():
                    out.append(_finding('VULNERABLE', 'CRITICAL',
                        f'Portainer Default Credentials ({user}:{passwd})',
                        f'Portainer /api/auth succeeded with {user}:{passwd} — '
                        'full Docker/container management access.',
                        target, resolved_ip, port,
                        url=f'{scheme}://{host}:{port}/api/auth',
                        http_status=r.status_code))
                    return out
            except Exception:
                pass
    return out


# ─── RabbitMQ Management (15672) ─────────────────────────────────────────────

async def check_rabbitmq(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(
                f'http://{host}:{port}/api/overview',
                auth=('guest', 'guest'))
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('rabbitmq', 'erlang', 'cluster_name')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL',
                    'RabbitMQ Management Default Credentials (guest:guest)',
                    'RabbitMQ /api/overview accessible with guest:guest — '
                    'full broker management access including message queues.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/overview',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── IPMI (623) ──────────────────────────────────────────────────────────────

async def check_ipmi(host, port, target, resolved_ip):
    out = []
    # Cipher 0 authentication bypass — no password required
    if _bin('ipmitool'):
        stdout, _, rc = await _run(
            ['ipmitool', '-I', 'lanplus', '-C', '0',
             '-H', host, '-U', 'root', '-P', '', 'user', 'list'],
            timeout=15)
        if rc == 0 and stdout and any(w in stdout.lower() for w in ('id', 'name', 'user')):
            out.append(_finding('VULNERABLE', 'CRITICAL', 'IPMI Cipher 0 Authentication Bypass',
                'ipmitool cipher 0 (no auth) user list succeeded — '
                'CVE-2013-4786 / IPMI 2.0 RAKP authentication bypass.',
                target, resolved_ip, port,
                url=f'ipmi://{host}:{port}'))
            return out

        # Try empty username/password
        stdout, _, rc = await _run(
            ['ipmitool', '-I', 'lanplus',
             '-H', host, '-U', '', '-P', '', 'user', 'list'],
            timeout=15)
        if rc == 0 and stdout and any(w in stdout.lower() for w in ('id', 'name', 'user')):
            out.append(_finding('VULNERABLE', 'CRITICAL', 'IPMI Empty Credentials Accepted',
                'ipmitool empty username/password user list succeeded — '
                'IPMI management interface accessible without credentials.',
                target, resolved_ip, port,
                url=f'ipmi://{host}:{port}'))
    return out


# ─── Nexus Repository (8081) ─────────────────────────────────────────────────

async def check_nexus(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /service/rest/v1/repositories — unauthenticated repository listing
        try:
            r = await client.get(f'http://{host}:{port}/service/rest/v1/repositories')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('name', 'format', 'type', 'url')
            ):
                out.append(_finding('VULNERABLE', 'HIGH', 'Nexus Repository List Unauthenticated',
                    'Nexus /service/rest/v1/repositories accessible without auth — '
                    'full repository list exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/service/rest/v1/repositories',
                    http_status=r.status_code))
        except Exception:
            pass

        # Try default creds admin:admin123
        try:
            r = await client.get(
                f'http://{host}:{port}/service/rest/v1/status',
                auth=('admin', 'admin123'))
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL',
                    'Nexus Repository Default Credentials (admin:admin123)',
                    'Nexus /service/rest/v1/status accessible with admin:admin123.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/service/rest/v1/status',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Artifactory (8081 / 8082) ───────────────────────────────────────────────

async def check_artifactory(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /artifactory/api/system/ping — detect service
        try:
            r = await client.get(f'http://{host}:{port}/artifactory/api/system/ping')
            if r.status_code == 200 and 'ok' in r.text.lower():
                out.append(_finding('INFO', 'INFO', 'JFrog Artifactory Detected',
                    f'Artifactory ping at /artifactory/api/system/ping responded OK.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/artifactory/api/system/ping',
                    http_status=r.status_code))
            else:
                return out
        except Exception:
            return out

        # /artifactory/api/repositories — unauthenticated repo listing
        try:
            r = await client.get(f'http://{host}:{port}/artifactory/api/repositories')
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'HIGH', 'Artifactory Repository List Unauthenticated',
                    'Artifactory /artifactory/api/repositories accessible without auth.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/artifactory/api/repositories',
                    http_status=r.status_code))
        except Exception:
            pass

        # Try default creds admin:password
        try:
            r = await client.get(
                f'http://{host}:{port}/artifactory/api/repositories',
                auth=('admin', 'password'))
            if r.status_code == 200:
                out.append(_finding('VULNERABLE', 'CRITICAL',
                    'Artifactory Default Credentials (admin:password)',
                    'Artifactory accessible with default credentials admin:password.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/artifactory/api/repositories',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── TeamCity (8111) ─────────────────────────────────────────────────────────

async def check_teamcity(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /app/rest/server — version and build info
        try:
            r = await client.get(f'http://{host}:{port}/app/rest/server')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('teamcity', 'version', 'buildnumber')
            ):
                out.append(_finding('VULNERABLE', 'HIGH', 'TeamCity REST API Unauthenticated',
                    'TeamCity /app/rest/server accessible without auth — '
                    'version and build configuration info exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/app/rest/server',
                    http_status=r.status_code))
            else:
                return out
        except Exception:
            return out

        # CVE-2024-27198 — authentication bypass to /app/rest/users
        try:
            r = await client.get(f'http://{host}:{port}/app/rest/users')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('user', 'username', 'id')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'TeamCity CVE-2024-27198 Auth Bypass',
                    'TeamCity /app/rest/users accessible without auth — '
                    'CVE-2024-27198 authentication bypass, full user listing exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/app/rest/users',
                    payload_url=f'http://{host}:{port}/app/rest/users',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── SonarQube (9000) ────────────────────────────────────────────────────────

async def check_sonarqube(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /api/system/status — service detection and version
        try:
            r = await client.get(f'http://{host}:{port}/api/system/status')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('sonarqube', 'status', 'version')
            ):
                out.append(_finding('INFO', 'INFO', 'SonarQube Detected',
                    f'SonarQube /api/system/status accessible: {r.text[:200]}',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/system/status',
                    http_status=r.status_code))
            else:
                return out
        except Exception:
            return out

        # /api/projects/search — project source code disclosure
        try:
            r = await client.get(f'http://{host}:{port}/api/projects/search')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('components', 'key', 'paging')
            ):
                out.append(_finding('VULNERABLE', 'HIGH', 'SonarQube Projects Unauthenticated',
                    'SonarQube /api/projects/search accessible without auth — '
                    'project source and analysis data exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/projects/search',
                    http_status=r.status_code))
        except Exception:
            pass

        # Try default admin:admin
        try:
            r = await client.post(
                f'http://{host}:{port}/api/authentication/login',
                data={'login': 'admin', 'password': 'admin'})
            if r.status_code == 200 and 'error' not in r.text.lower():
                out.append(_finding('VULNERABLE', 'CRITICAL',
                    'SonarQube Default Credentials (admin:admin)',
                    'SonarQube /api/authentication/login succeeded with admin:admin.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/api/authentication/login',
                    http_status=r.status_code))
        except Exception:
            pass
    return out


# ─── Istio / Envoy Admin (15000 / 15001) ─────────────────────────────────────

async def check_envoy_admin(host, port, target, resolved_ip):
    out = []
    async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
        # /config_dump — full mesh configuration
        try:
            r = await client.get(f'http://{host}:{port}/config_dump')
            if r.status_code == 200 and any(
                w in r.text.lower() for w in ('static_resources', 'dynamic_resources', 'configs')
            ):
                out.append(_finding('VULNERABLE', 'CRITICAL', 'Istio/Envoy Admin /config_dump Exposed',
                    'Envoy admin /config_dump accessible without auth — '
                    'full service mesh configuration including TLS certificates and routes exposed.',
                    target, resolved_ip, port,
                    url=f'http://{host}:{port}/config_dump',
                    http_status=r.status_code))
                return out
        except Exception:
            pass

        for path, label, severity in (
            ('/listeners', 'Envoy /listeners Exposed',  'HIGH'),
            ('/clusters',  'Envoy /clusters Exposed',   'HIGH'),
            ('/stats',     'Envoy /stats Accessible',   'INFO'),
        ):
            try:
                r = await client.get(f'http://{host}:{port}{path}')
                if r.status_code == 200:
                    out.append(_finding('VULNERABLE', severity, label,
                        f'Envoy admin {path} accessible without auth (HTTP {r.status_code}).',
                        target, resolved_ip, port,
                        url=f'http://{host}:{port}{path}',
                        http_status=r.status_code))
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
    623:   check_ipmi,
    636:   check_ldap,
    873:   check_rsync,
    902:   check_vmware,
    1433:  check_mssql,
    1521:  check_oracle,
    2049:  check_nfs,
    2181:  check_zookeeper,
    2375:  check_docker,
    2376:  check_docker,
    2379:  check_kubernetes,
    2380:  check_kubernetes,
    3100:  check_loki,
    3306:  check_mysql,
    3389:  check_rdp,
    4848:  check_glassfish,
    5432:  check_postgresql,
    5671:  check_activemq,
    5672:  check_activemq,
    5900:  check_vnc,
    5901:  check_vnc,
    5984:  check_couchdb,
    5985:  check_winrm,
    5986:  check_winrm,
    6379:  check_redis,
    6443:  check_kubernetes,
    7001:  check_weblogic,
    7002:  check_weblogic,
    8000:  check_splunk,
    8009:  check_ajp,
    8080:  check_spring_actuator,
    8081:  check_nexus,
    8082:  check_artifactory,
    8088:  check_hadoop_yarn,
    8089:  check_splunk,
    8090:  check_spring_actuator,
    8111:  check_teamcity,
    8200:  check_vault,
    8443:  check_spring_actuator,
    8500:  check_consul,
    8501:  check_consul,
    8778:  check_jolokia,
    8888:  check_jupyter,
    8889:  check_jupyter,
    8983:  check_solr,
    9000:  check_sonarqube,
    9001:  check_minio,
    9042:  check_cassandra,
    9092:  check_kafka,
    9093:  check_alertmanager,
    9160:  check_cassandra,
    9411:  check_zipkin,
    9443:  check_portainer,
    9870:  check_hadoop_hdfs,
    9990:  check_jboss,
    10250: check_kubernetes,
    11211: check_memcached,
    15000: check_envoy_admin,
    15001: check_envoy_admin,
    15672: check_rabbitmq,
    16686: check_jaeger,
    27017: check_mongodb,
    50070: check_hadoop_hdfs,
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
