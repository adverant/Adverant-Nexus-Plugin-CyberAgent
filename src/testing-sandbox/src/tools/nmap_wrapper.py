"""
Nmap Wrapper
Network scanning and service detection
"""

from typing import Dict, List, Any
from tools.base_wrapper import BaseToolWrapper


class NmapWrapper(BaseToolWrapper):
    """Nmap tool wrapper"""

    @property
    def tool_name(self) -> str:
        return 'nmap'

    @property
    def description(self) -> str:
        return 'Network reconnaissance and port scanning'

    @property
    def supported_actions(self) -> List[str]:
        return [
            'quick_scan',        # Fast port scan (-F)
            'full_scan',         # Full port scan (-p-)
            'service_detection', # Service version detection (-sV)
            'os_detection',      # OS detection (-O)
            'aggressive',        # Aggressive scan (-A)
            'vuln_scan',         # Vulnerability scanning (--script vuln)
            'default_scripts'    # Default NSE scripts (-sC)
        ]

    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """Execute Nmap scan"""
        if not self.validate_target(target):
            raise ValueError(f'Invalid target: {target}')

        if action not in self.supported_actions:
            raise ValueError(f'Unsupported action: {action}')

        # Base command
        cmd = ['nmap']

        # Action-specific flags
        if action == 'quick_scan':
            cmd.extend(['-F', '-T4'])
        elif action == 'full_scan':
            cmd.extend(['-p-', '-T4'])
        elif action == 'service_detection':
            cmd.extend(['-sV', '-T4'])
        elif action == 'os_detection':
            cmd.extend(['-O', '-T4'])
        elif action == 'aggressive':
            cmd.extend(['-A', '-T4'])
        elif action == 'vuln_scan':
            cmd.extend(['--script', 'vuln', '-T4'])
        elif action == 'default_scripts':
            cmd.extend(['-sC', '-T4'])

        # Add XML output for better parsing
        cmd.extend(['-oX', '-'])

        # Add custom options
        if options.get('ports'):
            cmd.extend(['-p', str(options['ports'])])

        if options.get('scripts'):
            cmd.extend(['--script', options['scripts']])

        if options.get('timing'):
            cmd.extend(['-T', str(options['timing'])])

        if options.get('skip_ping'):
            cmd.append('-Pn')

        # Add target
        cmd.append(target)

        # Execute
        command = ' '.join(cmd)
        self.logger.info(f'Running Nmap: {action} on {target}')

        try:
            output = await self.run_command(command, timeout=options.get('timeout', 1800))
            return output
        except Exception as e:
            self.logger.error(f'Nmap execution failed: {e}')
            raise
