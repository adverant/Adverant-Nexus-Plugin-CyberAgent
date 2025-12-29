"""
Static Malware Analyzer
Performs static analysis on malware samples without execution
"""

import pefile
import hashlib
from typing import Dict, List, Any
from pathlib import Path

from utils.logger import setup_logger

logger = setup_logger('static-analyzer')


class StaticAnalyzer:
    """Static malware analysis"""

    async def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform static analysis on file

        Returns:
            Dictionary containing:
            - file_info: Basic file information
            - hashes: MD5, SHA1, SHA256
            - pe_info: PE file structure (if PE)
            - strings: Extracted strings
            - entropy: File entropy
            - imports: Imported functions
            - exports: Exported functions
        """
        logger.info(f'Starting static analysis: {file_path}')

        results = {}

        # Basic file info
        results['file_info'] = self.get_file_info(file_path)

        # Compute hashes
        results['hashes'] = self.compute_hashes(file_path)

        # Extract strings
        results['strings'] = self.extract_strings(file_path)

        # PE analysis (if Windows executable)
        if file_path.endswith(('.exe', '.dll', '.sys')):
            results['pe_info'] = self.analyze_pe(file_path)

        logger.info(f'Static analysis completed: {file_path}')

        return results

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        import magic
        path = Path(file_path)

        return {
            'filename': path.name,
            'size': path.stat().st_size,
            'mime_type': magic.from_file(file_path, mime=True),
            'file_type': magic.from_file(file_path)
        }

    def compute_hashes(self, file_path: str) -> Dict[str, str]:
        """Compute file hashes"""
        with open(file_path, 'rb') as f:
            data = f.read()

        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }

    def extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from file"""
        import string

        printable = set(string.printable)
        strings = []

        with open(file_path, 'rb') as f:
            data = f.read()

        current_string = ''
        for byte in data:
            char = chr(byte)
            if char in printable:
                current_string += char
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ''

        return strings[:1000]  # Limit to 1000 strings

    def analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE file structure"""
        try:
            pe = pefile.PE(file_path)

            result = {
                'machine': pe.FILE_HEADER.Machine,
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'sections': [],
                'imports': [],
                'exports': [],
                'resources': []
            }

            # Sections
            for section in pe.sections:
                result['sections'].append({
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                })

            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            result['imports'].append(f"{dll_name}!{imp.name.decode('utf-8', errors='ignore')}")

            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result['exports'].append(exp.name.decode('utf-8', errors='ignore'))

            pe.close()

            return result

        except Exception as e:
            logger.error(f'PE analysis failed: {e}')
            return {'error': str(e)}
