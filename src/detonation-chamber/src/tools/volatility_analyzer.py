"""
Volatility Memory Forensics Analyzer
Performs memory forensics on memory dumps using Volatility 3
"""

import asyncio
import subprocess
from typing import Dict, List, Any
from pathlib import Path

from utils.logger import setup_logger

logger = setup_logger('volatility-analyzer')


class VolatilityAnalyzer:
    """Volatility 3 memory forensics analyzer"""

    def __init__(self):
        self.volatility_cmd = 'vol3'  # Volatility 3 command

    async def analyze(self, memory_dump_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive memory analysis

        Args:
            memory_dump_path: Path to memory dump file

        Returns:
            Dictionary containing analysis results
        """
        logger.info(f'Starting memory analysis: {memory_dump_path}')

        results = {}

        # Run multiple Volatility plugins
        plugins = [
            ('pslist', 'Process list'),
            ('pstree', 'Process tree'),
            ('netscan', 'Network connections'),
            ('malfind', 'Malicious code'),
            ('dlllist', 'DLL list'),
            ('handles', 'Open handles'),
            ('cmdline', 'Command lines'),
            ('filescan', 'File objects')
        ]

        for plugin, description in plugins:
            try:
                logger.info(f'Running Volatility plugin: {plugin}')
                result = await self.run_plugin(memory_dump_path, plugin)
                results[plugin] = result
            except Exception as e:
                logger.error(f'Plugin {plugin} failed: {e}')
                results[plugin] = {'error': str(e)}

        # Extract suspicious indicators
        results['suspicious_indicators'] = self.extract_indicators(results)

        logger.info(f'Memory analysis completed: {len(results)} plugins executed')

        return results

    async def run_plugin(self, memory_dump: str, plugin: str) -> Dict[str, Any]:
        """Run a specific Volatility plugin"""
        try:
            cmd = [
                'python3', '-m', 'volatility3',
                '-f', memory_dump,
                plugin,
                '--output', 'json'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 minutes per plugin
            )

            if process.returncode == 0:
                import json
                return json.loads(stdout.decode('utf-8', errors='ignore'))
            else:
                error_msg = stderr.decode('utf-8', errors='ignore')
                logger.warning(f'Plugin {plugin} returned error: {error_msg}')
                return {'error': error_msg}

        except asyncio.TimeoutError:
            logger.error(f'Plugin {plugin} timed out')
            return {'error': 'Timeout'}
        except Exception as e:
            logger.error(f'Plugin {plugin} failed: {e}')
            return {'error': str(e)}

    def extract_indicators(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract suspicious indicators from analysis results"""
        indicators = []

        # Check for code injection (malfind)
        if 'malfind' in results and not results['malfind'].get('error'):
            malfind_results = results['malfind']
            if malfind_results:
                indicators.append({
                    'type': 'code_injection',
                    'severity': 'high',
                    'description': f'Found {len(malfind_results)} suspicious memory regions',
                    'details': malfind_results
                })

        # Check for suspicious network connections
        if 'netscan' in results and not results['netscan'].get('error'):
            netscan_results = results['netscan']
            suspicious_ports = [4444, 31337, 8080, 443, 1337]

            for conn in netscan_results:
                if conn.get('LocalPort') in suspicious_ports:
                    indicators.append({
                        'type': 'suspicious_network',
                        'severity': 'medium',
                        'description': f'Suspicious port {conn["LocalPort"]} in use',
                        'details': conn
                    })

        # Check for hidden processes (compare pslist vs psscan)
        # This would require running both plugins and comparing

        return indicators
