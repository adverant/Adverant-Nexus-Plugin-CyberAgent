"""
Result Aggregator
Combines and summarizes results from multiple analysis tools
"""

from typing import Dict, Any


class ResultAggregator:
    """Aggregate analysis results from multiple tools"""

    def aggregate(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combine results from all analysis phases

        Args:
            results: Dictionary containing results from:
                - static_analysis
                - yara_matches
                - behavioral_analysis (Cuckoo)
                - memory_analysis (Volatility)
                - iocs

        Returns:
            Aggregated summary
        """
        summary = {
            'overall_score': self._calculate_overall_score(results),
            'threat_level': results.get('iocs', {}).get('threat_level', 'unknown'),
            'malware_family': results.get('iocs', {}).get('malware_family'),
            'analysis_phases': {
                'static': 'static_analysis' in results,
                'yara': 'yara_matches' in results,
                'behavioral': 'behavioral_analysis' in results,
                'memory': 'memory_analysis' in results,
                'iocs': 'iocs' in results
            },
            'key_findings': self._extract_key_findings(results),
            'ioc_summary': self._summarize_iocs(results.get('iocs', {})),
            'recommendations': self._generate_recommendations(results),
            'detailed_results': results
        }

        return summary

    def _calculate_overall_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall maliciousness score (0-100)"""
        score = 0.0

        # Cuckoo score (0-10, weight 30%)
        if 'behavioral_analysis' in results:
            cuckoo_score = results['behavioral_analysis'].get('score', 0)
            score += (cuckoo_score / 10) * 30

        # YARA matches (weight 25%)
        if 'yara_matches' in results:
            yara_count = len(results['yara_matches'])
            score += min(yara_count * 5, 25)

        # IOC count (weight 25%)
        if 'iocs' in results:
            ioc_count = sum(len(v) for v in results['iocs'].get('iocs', {}).values())
            score += min(ioc_count * 2, 25)

        # Suspicious API calls (weight 20%)
        if 'static_analysis' in results:
            suspicious_imports = len(results['static_analysis'].get('pe_info', {}).get('imports', []))
            score += min(suspicious_imports * 0.5, 20)

        return min(score, 100.0)

    def _extract_key_findings(self, results: Dict[str, Any]) -> list:
        """Extract top key findings"""
        findings = []

        # YARA matches
        if 'yara_matches' in results and results['yara_matches']:
            findings.append({
                'type': 'yara_detection',
                'severity': 'high',
                'description': f"Matched {len(results['yara_matches'])} YARA rules",
                'rules': [m['rule'] for m in results['yara_matches'][:5]]
            })

        # Network connections
        if 'behavioral_analysis' in results:
            network = results['behavioral_analysis'].get('network', {})
            tcp_count = len(network.get('tcp', []))
            if tcp_count > 0:
                findings.append({
                    'type': 'network_activity',
                    'severity': 'high',
                    'description': f"Made {tcp_count} network connections",
                    'connections': network.get('tcp', [])[:5]
                })

        # Code injection
        if 'memory_analysis' in results:
            malfind = results['memory_analysis'].get('malfind', [])
            if malfind and not isinstance(malfind, dict):
                findings.append({
                    'type': 'code_injection',
                    'severity': 'critical',
                    'description': f"Detected code injection in {len(malfind)} regions"
                })

        return findings

    def _summarize_iocs(self, iocs: Dict[str, Any]) -> Dict[str, int]:
        """Summarize IOC counts"""
        if not iocs or 'iocs' not in iocs:
            return {}

        return {
            ioc_type: len(ioc_list)
            for ioc_type, ioc_list in iocs['iocs'].items()
        }

    def _generate_recommendations(self, results: Dict[str, Any]) -> list:
        """Generate remediation recommendations"""
        recommendations = []

        threat_level = results.get('iocs', {}).get('threat_level', 'unknown')

        if threat_level in ['critical', 'high']:
            recommendations.append('Isolate affected systems immediately')
            recommendations.append('Block all network IOCs at firewall/IDS level')

        if 'iocs' in results and results['iocs'].get('iocs', {}).get('ip'):
            recommendations.append('Block malicious IP addresses')

        if 'iocs' in results and results['iocs'].get('iocs', {}).get('domain'):
            recommendations.append('Block malicious domains via DNS filtering')

        if threat_level != 'info':
            recommendations.append('Run full antivirus scan on affected systems')
            recommendations.append('Review logs for signs of lateral movement')
            recommendations.append('Change passwords for compromised accounts')

        return recommendations
