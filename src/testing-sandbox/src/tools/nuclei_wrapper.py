"""
Nuclei Wrapper
Fast vulnerability scanner with 6000+ templates
"""

from typing import Dict, List, Any
from tools.base_wrapper import BaseToolWrapper


class NucleiWrapper(BaseToolWrapper):
    """Nuclei tool wrapper"""

    @property
    def tool_name(self) -> str:
        return 'nuclei'

    @property
    def description(self) -> str:
        return 'Fast vulnerability scanner with 6000+ templates'

    @property
    def supported_actions(self) -> List[str]:
        return [
            'scan_cves',           # Scan for CVEs
            'scan_misconfigs',     # Scan for misconfigurations
            'scan_exposures',      # Scan for exposures
            'scan_all',            # Scan with all templates
            'scan_custom'          # Scan with custom templates
        ]

    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """Execute Nuclei scan"""
        if not self.validate_target(target):
            raise ValueError(f'Invalid target: {target}')

        if action not in self.supported_actions:
            raise ValueError(f'Unsupported action: {action}')

        # Base command
        cmd = ['nuclei', '-u', target]

        # Output as JSON lines
        cmd.extend(['-json', '-silent'])

        # Action-specific templates
        if action == 'scan_cves':
            cmd.extend(['-tags', 'cve'])
        elif action == 'scan_misconfigs':
            cmd.extend(['-tags', 'misconfiguration'])
        elif action == 'scan_exposures':
            cmd.extend(['-tags', 'exposure'])
        elif action == 'scan_all':
            cmd.extend(['-as'])  # All severity
        elif action == 'scan_custom':
            if options.get('templates'):
                cmd.extend(['-t', options['templates']])
            if options.get('tags'):
                cmd.extend(['-tags', options['tags']])

        # Severity filtering
        if options.get('severity'):
            cmd.extend(['-severity', options['severity']])

        # Concurrency
        if options.get('concurrency'):
            cmd.extend(['-c', str(options['concurrency'])])
        else:
            cmd.extend(['-c', '50'])  # Default

        # Rate limit
        if options.get('rate_limit'):
            cmd.extend(['-rl', str(options['rate_limit'])])
        else:
            cmd.extend(['-rl', '150'])  # Default

        # Execute
        command = ' '.join(cmd)
        self.logger.info(f'Running Nuclei: {action} on {target}')

        try:
            output = await self.run_command(command, timeout=options.get('timeout', 1800))
            return output
        except Exception as e:
            self.logger.error(f'Nuclei execution failed: {e}')
            raise
