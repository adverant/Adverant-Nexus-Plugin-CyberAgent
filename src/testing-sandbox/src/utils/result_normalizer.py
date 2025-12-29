"""
Result Normalizer
Converts tool-specific output formats to standardized JSON
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional


class ResultNormalizer:
    """Normalize security tool outputs to consistent JSON format"""

    def normalize(self, tool_name: str, raw_output: str) -> Dict[str, Any]:
        """
        Normalize tool output to standard format

        Args:
            tool_name: Name of the tool
            raw_output: Raw tool output

        Returns:
            Normalized results as dictionary
        """
        normalizer_map = {
            'nmap': self._normalize_nmap,
            'nuclei': self._normalize_nuclei,
            'sqlmap': self._normalize_sqlmap,
            'nikto': self._normalize_nikto,
            'burp': self._normalize_burp,
            'hashcat': self._normalize_hashcat,
            'hydra': self._normalize_hydra
        }

        normalizer = normalizer_map.get(tool_name, self._normalize_generic)
        return normalizer(raw_output)

    def _normalize_nmap(self, raw_output: str) -> Dict[str, Any]:
        """Normalize Nmap output"""
        results = {
            'tool': 'nmap',
            'findings': [],
            'summary': {}
        }

        try:
            # Try to parse XML output if available
            if '<nmaprun' in raw_output:
                root = ET.fromstring(raw_output)

                for host in root.findall('host'):
                    host_data = {
                        'ip': None,
                        'hostname': None,
                        'state': None,
                        'ports': [],
                        'os': None
                    }

                    # IP address
                    address = host.find('address')
                    if address is not None:
                        host_data['ip'] = address.get('addr')

                    # Hostname
                    hostnames = host.find('hostnames')
                    if hostnames is not None:
                        hostname = hostnames.find('hostname')
                        if hostname is not None:
                            host_data['hostname'] = hostname.get('name')

                    # Host state
                    status = host.find('status')
                    if status is not None:
                        host_data['state'] = status.get('state')

                    # Ports
                    ports = host.find('ports')
                    if ports is not None:
                        for port in ports.findall('port'):
                            state = port.find('state')
                            service = port.find('service')

                            port_data = {
                                'port': int(port.get('portid')),
                                'protocol': port.get('protocol'),
                                'state': state.get('state') if state is not None else 'unknown',
                                'service': service.get('name') if service is not None else 'unknown',
                                'version': service.get('version') if service is not None else None
                            }

                            host_data['ports'].append(port_data)

                    # OS detection
                    os = host.find('os')
                    if os is not None:
                        osmatch = os.find('osmatch')
                        if osmatch is not None:
                            host_data['os'] = osmatch.get('name')

                    results['findings'].append(host_data)

                # Summary
                results['summary'] = {
                    'total_hosts': len(results['findings']),
                    'hosts_up': sum(1 for h in results['findings'] if h['state'] == 'up'),
                    'total_ports': sum(len(h['ports']) for h in results['findings']),
                    'open_ports': sum(
                        sum(1 for p in h['ports'] if p['state'] == 'open')
                        for h in results['findings']
                    )
                }

            else:
                # Parse text output (fallback)
                results['raw_output'] = raw_output
                results['summary'] = {'parsed': False, 'format': 'text'}

        except Exception as e:
            results['parse_error'] = str(e)
            results['raw_output'] = raw_output[:1000]

        return results

    def _normalize_nuclei(self, raw_output: str) -> Dict[str, Any]:
        """Normalize Nuclei output"""
        results = {
            'tool': 'nuclei',
            'findings': [],
            'summary': {}
        }

        try:
            # Nuclei outputs JSON lines
            for line in raw_output.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        finding = {
                            'template_id': data.get('template-id'),
                            'template_name': data.get('info', {}).get('name'),
                            'severity': data.get('info', {}).get('severity', 'info'),
                            'matched_at': data.get('matched-at'),
                            'matcher_name': data.get('matcher-name'),
                            'type': data.get('type'),
                            'curl_command': data.get('curl-command'),
                            'host': data.get('host'),
                            'timestamp': data.get('timestamp')
                        }
                        results['findings'].append(finding)
                    except json.JSONDecodeError:
                        continue

            # Summary
            severity_counts = {}
            for finding in results['findings']:
                sev = finding['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            results['summary'] = {
                'total_findings': len(results['findings']),
                'severity_counts': severity_counts,
                'unique_templates': len(set(f['template_id'] for f in results['findings']))
            }

        except Exception as e:
            results['parse_error'] = str(e)
            results['raw_output'] = raw_output[:1000]

        return results

    def _normalize_sqlmap(self, raw_output: str) -> Dict[str, Any]:
        """Normalize SQLMap output"""
        results = {
            'tool': 'sqlmap',
            'findings': [],
            'summary': {}
        }

        try:
            # Extract vulnerabilities
            vulnerable = 'SQL injection' in raw_output or 'injectable' in raw_output.lower()

            if vulnerable:
                # Extract details using regex
                param_pattern = r"Parameter: ([^\s]+)"
                type_pattern = r"Type: ([^\n]+)"
                title_pattern = r"Title: ([^\n]+)"
                payload_pattern = r"Payload: ([^\n]+)"

                params = re.findall(param_pattern, raw_output)
                types = re.findall(type_pattern, raw_output)
                titles = re.findall(title_pattern, raw_output)
                payloads = re.findall(payload_pattern, raw_output)

                for i in range(max(len(params), len(types), len(titles))):
                    finding = {
                        'parameter': params[i] if i < len(params) else 'unknown',
                        'injection_type': types[i] if i < len(types) else 'unknown',
                        'title': titles[i] if i < len(titles) else 'SQL Injection',
                        'payload': payloads[i] if i < len(payloads) else None,
                        'severity': 'critical'
                    }
                    results['findings'].append(finding)

            # Summary
            results['summary'] = {
                'vulnerable': vulnerable,
                'total_findings': len(results['findings']),
                'dbms': self._extract_dbms(raw_output)
            }

        except Exception as e:
            results['parse_error'] = str(e)
            results['raw_output'] = raw_output[:1000]

        return results

    def _normalize_nikto(self, raw_output: str) -> Dict[str, Any]:
        """Normalize Nikto output"""
        results = {
            'tool': 'nikto',
            'findings': [],
            'summary': {}
        }

        try:
            # Parse Nikto findings (+ marks findings)
            for line in raw_output.split('\n'):
                if line.strip().startswith('+'):
                    finding = {
                        'description': line.strip()[1:].strip(),
                        'severity': self._classify_nikto_severity(line)
                    }
                    results['findings'].append(finding)

            # Summary
            severity_counts = {}
            for finding in results['findings']:
                sev = finding['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            results['summary'] = {
                'total_findings': len(results['findings']),
                'severity_counts': severity_counts
            }

        except Exception as e:
            results['parse_error'] = str(e)
            results['raw_output'] = raw_output[:1000]

        return results

    def _normalize_burp(self, raw_output: str) -> Dict[str, Any]:
        """Normalize Burp Suite output"""
        results = {
            'tool': 'burp',
            'findings': [],
            'summary': {}
        }

        try:
            # Burp outputs XML
            root = ET.fromstring(raw_output)

            for issue in root.findall('.//issue'):
                finding = {
                    'name': issue.findtext('name'),
                    'host': issue.findtext('host'),
                    'path': issue.findtext('path'),
                    'severity': issue.findtext('severity', 'info'),
                    'confidence': issue.findtext('confidence', 'certain'),
                    'issue_background': issue.findtext('issueBackground'),
                    'remediation_background': issue.findtext('remediationBackground')
                }
                results['findings'].append(finding)

            # Summary
            severity_counts = {}
            for finding in results['findings']:
                sev = finding['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            results['summary'] = {
                'total_findings': len(results['findings']),
                'severity_counts': severity_counts
            }

        except Exception as e:
            results['parse_error'] = str(e)
            results['raw_output'] = raw_output[:1000]

        return results

    def _normalize_hashcat(self, raw_output: str) -> Dict[str, Any]:
        """Normalize Hashcat output"""
        results = {
            'tool': 'hashcat',
            'findings': [],
            'summary': {}
        }

        try:
            # Extract cracked hashes
            for line in raw_output.split('\n'):
                if ':' in line and not line.startswith('['):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        finding = {
                            'hash': parts[0].strip(),
                            'plaintext': parts[1].strip(),
                            'severity': 'medium'
                        }
                        results['findings'].append(finding)

            # Summary
            results['summary'] = {
                'total_cracked': len(results['findings'])
            }

        except Exception as e:
            results['parse_error'] = str(e)
            results['raw_output'] = raw_output[:1000]

        return results

    def _normalize_hydra(self, raw_output: str) -> Dict[str, Any]:
        """Normalize Hydra output"""
        results = {
            'tool': 'hydra',
            'findings': [],
            'summary': {}
        }

        try:
            # Extract successful logins
            for line in raw_output.split('\n'):
                if 'login:' in line.lower() and 'password:' in line.lower():
                    # Extract credentials
                    login_match = re.search(r'login:\s*([^\s]+)', line, re.IGNORECASE)
                    pass_match = re.search(r'password:\s*([^\s]+)', line, re.IGNORECASE)

                    if login_match and pass_match:
                        finding = {
                            'username': login_match.group(1),
                            'password': pass_match.group(1),
                            'severity': 'high'
                        }
                        results['findings'].append(finding)

            # Summary
            results['summary'] = {
                'credentials_found': len(results['findings'])
            }

        except Exception as e:
            results['parse_error'] = str(e)
            results['raw_output'] = raw_output[:1000]

        return results

    def _normalize_generic(self, raw_output: str) -> Dict[str, Any]:
        """Generic normalization for unsupported tools"""
        return {
            'tool': 'unknown',
            'raw_output': raw_output[:10000],  # Limit size
            'summary': {'parsed': False}
        }

    def _extract_dbms(self, output: str) -> Optional[str]:
        """Extract DBMS type from SQLMap output"""
        dbms_pattern = r"back-end DBMS:\s*([^\n]+)"
        match = re.search(dbms_pattern, output, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _classify_nikto_severity(self, line: str) -> str:
        """Classify Nikto finding severity based on keywords"""
        line_lower = line.lower()

        critical_keywords = ['sql injection', 'remote code execution', 'rce']
        high_keywords = ['authentication bypass', 'directory traversal', 'file inclusion']
        medium_keywords = ['information disclosure', 'clickjacking', 'missing header']

        for keyword in critical_keywords:
            if keyword in line_lower:
                return 'critical'

        for keyword in high_keywords:
            if keyword in line_lower:
                return 'high'

        for keyword in medium_keywords:
            if keyword in line_lower:
                return 'medium'

        return 'info'
