"""
YARA Scanner
Scans files using YARA rules for malware identification
"""

import yara
from typing import Dict, List, Any
from pathlib import Path
import os

from utils.logger import setup_logger

logger = setup_logger('yara-scanner')


class YaraScanner:
    """YARA malware scanner"""

    def __init__(self):
        self.rules_path = Path(os.getenv('YARA_RULES_PATH', '/app/yara-rules'))
        self.compiled_rules = None
        self.load_rules()

    def load_rules(self):
        """Load and compile YARA rules"""
        try:
            if not self.rules_path.exists():
                logger.warning(f'YARA rules path does not exist: {self.rules_path}')
                return

            # Find all .yar and .yara files
            rule_files = {}
            for rule_file in self.rules_path.rglob('*.yar*'):
                namespace = str(rule_file.relative_to(self.rules_path)).replace('/', '_').replace('.yar', '')
                rule_files[namespace] = str(rule_file)

            if rule_files:
                self.compiled_rules = yara.compile(filepaths=rule_files)
                logger.info(f'Loaded {len(rule_files)} YARA rule files')
            else:
                logger.warning('No YARA rules found')

        except Exception as e:
            logger.error(f'Failed to load YARA rules: {e}', exc_info=True)

    async def scan(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan file with YARA rules

        Args:
            file_path: Path to file to scan

        Returns:
            List of YARA matches
        """
        if not self.compiled_rules:
            logger.warning('No YARA rules loaded, skipping scan')
            return []

        try:
            logger.info(f'Scanning with YARA: {file_path}')

            matches = self.compiled_rules.match(file_path)

            results = []
            for match in matches:
                result = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags),
                    'meta': dict(match.meta),
                    'strings': [
                        {
                            'identifier': s[1],
                            'data': s[2].decode('utf-8', errors='ignore') if isinstance(s[2], bytes) else str(s[2]),
                            'offset': s[0]
                        }
                        for s in match.strings
                    ]
                }
                results.append(result)

            logger.info(f'YARA scan complete: {len(results)} matches found')

            return results

        except Exception as e:
            logger.error(f'YARA scan failed: {e}', exc_info=True)
            return []

    def generate_rule(self, sample_path: str, rule_name: str) -> str:
        """
        Generate YARA rule from malware sample

        Args:
            sample_path: Path to malware sample
            rule_name: Name for the generated rule

        Returns:
            YARA rule as string
        """
        try:
            with open(sample_path, 'rb') as f:
                data = f.read()

            # Extract unique strings (basic implementation)
            unique_strings = self.extract_unique_strings(data)

            # Generate rule
            rule = f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated rule for {sample_path}"
        author = "Nexus-CyberAgent"
        date = "{os.path.getmtime(sample_path)}"

    strings:
"""

            for i, string in enumerate(unique_strings[:20]):  # Limit to 20 strings
                rule += f'        $s{i} = "{string}"\n'

            rule += """
    condition:
        3 of them
}
"""

            logger.info(f'Generated YARA rule: {rule_name}')

            return rule

        except Exception as e:
            logger.error(f'Failed to generate YARA rule: {e}')
            return ''

    def extract_unique_strings(self, data: bytes, min_length: int = 8) -> List[str]:
        """Extract unique printable strings from binary data"""
        import re
        import string

        printable = set(string.printable)
        strings = re.findall(b'[\x20-\x7e]{' + str(min_length).encode() + b',}', data)

        unique = set()
        for s in strings:
            try:
                decoded = s.decode('ascii')
                if all(c in printable for c in decoded):
                    unique.add(decoded)
            except:
                pass

        return sorted(list(unique))[:50]  # Return top 50
