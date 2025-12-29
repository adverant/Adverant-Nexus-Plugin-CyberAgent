"""
Nikto Wrapper
Web server scanner
"""

from typing import Dict, List, Any
from tools.base_wrapper import BaseToolWrapper


class NiktoWrapper(BaseToolWrapper):
    """Nikto tool wrapper"""

    @property
    def tool_name(self) -> str:
        return 'nikto'

    @property
    def description(self) -> str:
        return 'Web server scanner for known vulnerabilities'

    @property
    def supported_actions(self) -> List[str]:
        return [
            'scan_web',            # Standard web scan
            'scan_ssl',            # SSL/TLS specific scan
            'scan_headers',        # HTTP header analysis
            'scan_cgi',            # CGI vulnerability scan
            'scan_all'             # Full scan (all tests)
        ]

    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """Execute Nikto scan"""
        if not self.validate_target(target):
            raise ValueError(f'Invalid target: {target}')

        if action not in self.supported_actions:
            raise ValueError(f'Unsupported action: {action}')

        # Base command
        cmd = ['nikto', '-h', target]

        # Action-specific tuning
        if action == 'scan_web':
            cmd.extend(['-Tuning', '1,2,3,4,5,6'])
        elif action == 'scan_ssl':
            cmd.extend(['-Tuning', '2', '-ssl'])
        elif action == 'scan_headers':
            cmd.extend(['-Tuning', '4'])
        elif action == 'scan_cgi':
            cmd.extend(['-Tuning', '8'])
        elif action == 'scan_all':
            cmd.extend(['-Tuning', 'x'])  # All tests

        # Output format
        cmd.extend(['-Format', 'txt'])

        # Additional options
        if options.get('port'):
            cmd.extend(['-port', str(options['port'])])

        if options.get('useragent'):
            cmd.extend(['-useragent', options['useragent']])

        if options.get('timeout'):
            cmd.extend(['-timeout', str(options['timeout'])])

        # Execute
        command = ' '.join(cmd)
        self.logger.info(f'Running Nikto: {action} on {target}')

        try:
            output = await self.run_command(command, timeout=options.get('timeout', 1800))
            return output
        except Exception as e:
            self.logger.error(f'Nikto execution failed: {e}')
            raise
