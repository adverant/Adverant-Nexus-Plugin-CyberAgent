"""
Hydra Wrapper
Network authentication cracking
"""

from typing import Dict, List, Any
from tools.base_wrapper import BaseToolWrapper


class HydraWrapper(BaseToolWrapper):
    """Hydra tool wrapper"""

    @property
    def tool_name(self) -> str:
        return 'hydra'

    @property
    def description(self) -> str:
        return 'Network authentication brute forcing tool'

    @property
    def supported_actions(self) -> List[str]:
        return [
            'crack_ssh',           # SSH authentication
            'crack_ftp',           # FTP authentication
            'crack_http',          # HTTP basic auth
            'crack_http_post',     # HTTP POST form
            'crack_mysql',         # MySQL authentication
            'crack_postgres',      # PostgreSQL authentication
            'crack_rdp',           # RDP authentication
            'crack_smb'            # SMB authentication
        ]

    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """Execute Hydra password cracking"""
        if not self.validate_target(target):
            raise ValueError(f'Invalid target: {target}')

        if action not in self.supported_actions:
            raise ValueError(f'Unsupported action: {action}')

        # Service mapping
        services = {
            'crack_ssh': 'ssh',
            'crack_ftp': 'ftp',
            'crack_http': 'http-get',
            'crack_http_post': 'http-post-form',
            'crack_mysql': 'mysql',
            'crack_postgres': 'postgres',
            'crack_rdp': 'rdp',
            'crack_smb': 'smb'
        }

        # Base command
        cmd = ['hydra']

        # Username/password options
        if options.get('username'):
            cmd.extend(['-l', options['username']])
        elif options.get('username_list'):
            cmd.extend(['-L', options['username_list']])
        else:
            cmd.extend(['-l', 'admin'])  # Default

        if options.get('password'):
            cmd.extend(['-p', options['password']])
        elif options.get('password_list'):
            cmd.extend(['-P', options['password_list']])
        else:
            cmd.extend(['-P', '/usr/share/wordlists/rockyou.txt'])  # Default

        # Threads
        threads = options.get('threads', 16)
        cmd.extend(['-t', str(threads)])

        # Verbose output
        cmd.append('-V')

        # Service-specific options
        if action == 'crack_http_post' and options.get('form'):
            cmd.append(options['form'])

        # Target
        cmd.append(target)

        # Service
        cmd.append(services[action])

        # Port (optional)
        if options.get('port'):
            cmd.extend(['-s', str(options['port'])])

        # Execute
        command = ' '.join(cmd)
        self.logger.info(f'Running Hydra: {action} on {target}')

        try:
            output = await self.run_command(command, timeout=options.get('timeout', 1800))
            return output
        except Exception as e:
            self.logger.error(f'Hydra execution failed: {e}')
            raise
