"""
Hashcat Wrapper
Password cracking
"""

from typing import Dict, List, Any
from tools.base_wrapper import BaseToolWrapper


class HashcatWrapper(BaseToolWrapper):
    """Hashcat tool wrapper"""

    @property
    def tool_name(self) -> str:
        return 'hashcat'

    @property
    def description(self) -> str:
        return 'Advanced password cracking tool'

    @property
    def supported_actions(self) -> List[str]:
        return [
            'crack_md5',           # MD5 hashes
            'crack_sha1',          # SHA1 hashes
            'crack_sha256',        # SHA256 hashes
            'crack_ntlm',          # NTLM hashes
            'crack_bcrypt',        # bcrypt hashes
            'crack_custom'         # Custom hash type
        ]

    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """Execute Hashcat password cracking"""
        if not target:
            raise ValueError('Hash or hash file required')

        if action not in self.supported_actions:
            raise ValueError(f'Unsupported action: {action}')

        # Hash mode mapping
        hash_modes = {
            'crack_md5': '0',
            'crack_sha1': '100',
            'crack_sha256': '1400',
            'crack_ntlm': '1000',
            'crack_bcrypt': '3200'
        }

        # Base command
        cmd = ['hashcat']

        # Hash mode
        if action == 'crack_custom':
            if options.get('hash_mode'):
                cmd.extend(['-m', str(options['hash_mode'])])
            else:
                raise ValueError('hash_mode required for custom action')
        else:
            cmd.extend(['-m', hash_modes[action]])

        # Attack mode (dictionary by default)
        attack_mode = options.get('attack_mode', '0')  # 0 = dictionary
        cmd.extend(['-a', str(attack_mode)])

        # Hash (from target)
        cmd.append(target)

        # Wordlist
        wordlist = options.get('wordlist', '/usr/share/wordlists/rockyou.txt')
        cmd.append(wordlist)

        # Additional options
        if options.get('rules'):
            cmd.extend(['-r', options['rules']])

        if options.get('optimized'):
            cmd.append('-O')

        if options.get('show'):
            cmd.append('--show')

        # Force CPU-only mode (no GPU in container)
        cmd.append('-D 1')

        # Execute
        command = ' '.join(cmd)
        self.logger.info(f'Running Hashcat: {action}')

        try:
            output = await self.run_command(command, timeout=options.get('timeout', 3600))
            return output
        except Exception as e:
            self.logger.error(f'Hashcat execution failed: {e}')
            raise
