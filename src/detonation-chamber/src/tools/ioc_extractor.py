"""
IOC Extractor
Extracts Indicators of Compromise from malware analysis results
"""

import re
from typing import Dict, List, Any, Set
from collections import defaultdict

from utils.logger import setup_logger

logger = setup_logger('ioc-extractor')


class IOCExtractor:
    """Extract IOCs from analysis results"""

    def __init__(self):
        # Regex patterns for IOC extraction
        self.patterns = {
            'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'registry': re.compile(r'(?:HKEY_[A-Z_]+\\[^\s]+|HKLM\\[^\s]+|HKCU\\[^\s]+)'),
            'mutex': re.compile(r'(?:Global\\|Local\\)[^\s<>"]+'),
            'file_path': re.compile(r'(?:C:\\|\\\\)[^<>"|?*\n]+')
        }

        # Known malicious indicators (example - would be loaded from threat intelligence)
        self.known_malicious_ips = set()
        self.known_malicious_domains = set()

    def extract_iocs(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract IOCs from complete analysis results

        Args:
            analysis_results: Combined results from all analysis phases

        Returns:
            Dictionary containing:
            - iocs: IOCs by type
            - confidence_scores: Confidence for each IOC
            - yara_matches: YARA rule matches
            - malware_family: Identified malware family
            - threat_level: Overall threat assessment
        """
        logger.info('Extracting IOCs from analysis results')

        iocs = defaultdict(set)

        # Extract from static analysis
        if 'static_analysis' in analysis_results:
            self._extract_from_static(analysis_results['static_analysis'], iocs)

        # Extract from YARA matches
        yara_matches = []
        if 'yara_matches' in analysis_results:
            yara_matches = [match['rule'] for match in analysis_results['yara_matches']]
            self._extract_from_yara(analysis_results['yara_matches'], iocs)

        # Extract from Cuckoo behavioral analysis
        if 'behavioral_analysis' in analysis_results:
            self._extract_from_behavioral(analysis_results['behavioral_analysis'], iocs)

        # Extract from memory analysis
        if 'memory_analysis' in analysis_results:
            self._extract_from_memory(analysis_results['memory_analysis'], iocs)

        # Convert sets to sorted lists
        iocs_lists = {key: sorted(list(values)) for key, values in iocs.items()}

        # Calculate confidence scores
        confidence_scores = self._calculate_confidence(iocs_lists, analysis_results)

        # Identify malware family
        malware_family = self._identify_malware_family(yara_matches, analysis_results)

        # Assess threat level
        threat_level = self._assess_threat_level(iocs_lists, yara_matches, analysis_results)

        logger.info(f'IOC extraction complete', extra={
            'total_iocs': sum(len(v) for v in iocs_lists.values()),
            'malware_family': malware_family,
            'threat_level': threat_level
        })

        return {
            'iocs': iocs_lists,
            'confidence_scores': confidence_scores,
            'yara_matches': yara_matches,
            'malware_family': malware_family,
            'threat_level': threat_level
        }

    def _extract_from_static(self, static_analysis: Dict[str, Any], iocs: Dict[str, Set]):
        """Extract IOCs from static analysis"""
        # Extract from strings
        if 'strings' in static_analysis:
            for string in static_analysis['strings']:
                self._extract_from_text(string, iocs)

        # Extract from PE imports
        if 'imports' in static_analysis:
            suspicious_imports = [
                'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                'LoadLibrary', 'GetProcAddress', 'WinExec', 'ShellExecute'
            ]
            for imp in static_analysis.get('imports', []):
                if any(susp in imp for susp in suspicious_imports):
                    iocs['suspicious_api'].add(imp)

    def _extract_from_yara(self, yara_matches: List[Dict[str, Any]], iocs: Dict[str, Set]):
        """Extract IOCs from YARA matches"""
        for match in yara_matches:
            # Extract strings matched by YARA rules
            for string_match in match.get('strings', []):
                data = string_match.get('data', '')
                self._extract_from_text(data, iocs)

            # Extract malware family from tags
            for tag in match.get('tags', []):
                if tag.lower() in ['apt', 'ransomware', 'trojan', 'backdoor']:
                    iocs['malware_type'].add(tag)

    def _extract_from_behavioral(self, behavioral: Dict[str, Any], iocs: Dict[str, Set]):
        """Extract IOCs from Cuckoo behavioral analysis"""
        # Extract network IOCs
        network = behavioral.get('network', {})

        for tcp_conn in network.get('tcp', []):
            if 'dst' in tcp_conn:
                iocs['ip'].add(tcp_conn['dst'])

        for dns_query in network.get('dns', []):
            if 'request' in dns_query:
                iocs['domain'].add(dns_query['request'])

        for http_req in network.get('http', []):
            if 'uri' in http_req:
                iocs['url'].add(http_req['uri'])
            if 'host' in http_req:
                iocs['domain'].add(http_req['host'])

        # Extract file IOCs
        for dropped_file in behavioral.get('dropped_files', []):
            iocs['md5'].add(dropped_file.get('md5', ''))
            iocs['sha256'].add(dropped_file.get('sha256', ''))

        # Extract registry modifications
        for process in behavioral.get('processes', []):
            if 'command_line' in process:
                self._extract_from_text(process['command_line'], iocs)

    def _extract_from_memory(self, memory_analysis: Dict[str, Any], iocs: Dict[str, Set]):
        """Extract IOCs from memory forensics"""
        # Extract from network connections
        if 'netscan' in memory_analysis:
            for conn in memory_analysis['netscan']:
                if 'ForeignAddr' in conn:
                    iocs['ip'].add(conn['ForeignAddr'])

        # Extract from handles (mutexes, files)
        if 'handles' in memory_analysis:
            for handle in memory_analysis['handles']:
                if handle.get('Type') == 'Mutant':
                    iocs['mutex'].add(handle.get('Name', ''))

        # Extract from malfind (code injection)
        if 'malfind' in memory_analysis:
            for finding in memory_analysis['malfind']:
                iocs['code_injection'].add(f"PID:{finding.get('pid')}")

    def _extract_from_text(self, text: str, iocs: Dict[str, Set]):
        """Extract IOCs from text using regex patterns"""
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                # Filter out private IPs and localhost
                if ioc_type == 'ip':
                    if not self._is_private_ip(match):
                        iocs[ioc_type].add(match)
                elif ioc_type == 'domain':
                    if not self._is_internal_domain(match):
                        iocs[ioc_type].add(match)
                else:
                    iocs[ioc_type].add(match)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        parts = ip.split('.')
        if len(parts) != 4:
            return True

        first = int(parts[0])
        second = int(parts[1])

        # Private IP ranges
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:  # Localhost
            return True

        return False

    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain is internal/common"""
        internal_tlds = ['.local', '.internal', '.lan']
        common_domains = ['microsoft.com', 'windows.com', 'google.com']

        domain_lower = domain.lower()

        if any(domain_lower.endswith(tld) for tld in internal_tlds):
            return True

        if any(common in domain_lower for common in common_domains):
            return True

        return False

    def _calculate_confidence(self, iocs: Dict[str, List], analysis_results: Dict) -> Dict[str, float]:
        """Calculate confidence score for each IOC type"""
        confidence = {}

        for ioc_type, ioc_list in iocs.items():
            if not ioc_list:
                confidence[ioc_type] = 0.0
                continue

            # Base confidence
            score = 0.5

            # Increase confidence if found in multiple sources
            sources = 0
            if 'static_analysis' in analysis_results:
                sources += 1
            if 'behavioral_analysis' in analysis_results:
                sources += 1
            if 'memory_analysis' in analysis_results:
                sources += 1

            score += (sources - 1) * 0.15

            # Increase for known malicious indicators
            if ioc_type == 'ip' and any(ip in self.known_malicious_ips for ip in ioc_list):
                score += 0.3
            if ioc_type == 'domain' and any(d in self.known_malicious_domains for d in ioc_list):
                score += 0.3

            confidence[ioc_type] = min(score, 1.0)

        return confidence

    def _identify_malware_family(self, yara_matches: List[str], analysis_results: Dict) -> Optional[str]:
        """Identify malware family from YARA matches and behavioral patterns"""
        # Check YARA rules for family names
        family_keywords = ['emotet', 'trickbot', 'ryuk', 'lockbit', 'cobalt_strike', 'ransomware']

        for match in yara_matches:
            match_lower = match.lower()
            for keyword in family_keywords:
                if keyword in match_lower:
                    return keyword.upper()

        # Check behavioral patterns
        if 'behavioral_analysis' in analysis_results:
            signatures = analysis_results['behavioral_analysis'].get('signatures', [])
            for sig in signatures:
                sig_name = sig.get('name', '').lower()
                for keyword in family_keywords:
                    if keyword in sig_name:
                        return keyword.upper()

        return None

    def _assess_threat_level(self, iocs: Dict[str, List], yara_matches: List[str], analysis_results: Dict) -> str:
        """Assess overall threat level"""
        score = 0

        # Score based on IOC types
        if iocs.get('ip'):
            score += len(iocs['ip']) * 2
        if iocs.get('domain'):
            score += len(iocs['domain']) * 2
        if iocs.get('code_injection'):
            score += len(iocs['code_injection']) * 5
        if iocs.get('suspicious_api'):
            score += len(iocs['suspicious_api']) * 1

        # Score based on YARA matches
        score += len(yara_matches) * 10

        # Score based on Cuckoo score
        if 'behavioral_analysis' in analysis_results:
            cuckoo_score = analysis_results['behavioral_analysis'].get('score', 0)
            score += cuckoo_score / 10

        # Classify threat level
        if score >= 50:
            return 'critical'
        elif score >= 30:
            return 'high'
        elif score >= 15:
            return 'medium'
        elif score >= 5:
            return 'low'
        else:
            return 'info'
