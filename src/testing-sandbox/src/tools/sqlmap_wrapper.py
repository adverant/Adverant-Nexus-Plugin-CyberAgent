"""
SQLMap Wrapper
SQL injection detection and exploitation
"""

from typing import Dict, List, Any
from tools.base_wrapper import BaseToolWrapper


class SQLMapWrapper(BaseToolWrapper):
    """SQLMap tool wrapper"""

    @property
    def tool_name(self) -> str:
        return 'sqlmap'

    @property
    def description(self) -> str:
        return 'SQL injection detection and exploitation'

    @property
    def supported_actions(self) -> List[str]:
        return [
            'test_injection',      # Test for SQL injection
            'enumerate_dbs',       # Enumerate databases
            'enumerate_tables',    # Enumerate tables
            'enumerate_columns',   # Enumerate columns
            'dump_table',          # Dump table data
            'dump_all',            # Dump entire database
            'os_shell'             # Attempt OS shell
        ]

    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """Execute SQLMap scan"""
        if not self.validate_target(target):
            raise ValueError(f'Invalid target: {target}')

        if action not in self.supported_actions:
            raise ValueError(f'Unsupported action: {action}')

        # Base command
        cmd = ['sqlmap', '-u', target]

        # Non-interactive mode
        cmd.extend(['--batch', '--random-agent'])

        # Action-specific flags
        if action == 'test_injection':
            cmd.extend(['--level=3', '--risk=2'])
        elif action == 'enumerate_dbs':
            cmd.append('--dbs')
        elif action == 'enumerate_tables':
            if options.get('database'):
                cmd.extend(['-D', options['database'], '--tables'])
            else:
                cmd.append('--tables')
        elif action == 'enumerate_columns':
            if options.get('database') and options.get('table'):
                cmd.extend([
                    '-D', options['database'],
                    '-T', options['table'],
                    '--columns'
                ])
        elif action == 'dump_table':
            if options.get('database') and options.get('table'):
                cmd.extend([
                    '-D', options['database'],
                    '-T', options['table'],
                    '--dump'
                ])
        elif action == 'dump_all':
            cmd.append('--dump-all')
        elif action == 'os_shell':
            cmd.append('--os-shell')

        # Additional options
        if options.get('data'):
            cmd.extend(['--data', options['data']])

        if options.get('cookie'):
            cmd.extend(['--cookie', options['cookie']])

        if options.get('threads'):
            cmd.extend(['--threads', str(options['threads'])])

        if options.get('dbms'):
            cmd.extend(['--dbms', options['dbms']])

        # Execute
        command = ' '.join(cmd)
        self.logger.info(f'Running SQLMap: {action} on {target}')

        try:
            output = await self.run_command(command, timeout=options.get('timeout', 1800))
            return output
        except Exception as e:
            self.logger.error(f'SQLMap execution failed: {e}')
            raise
