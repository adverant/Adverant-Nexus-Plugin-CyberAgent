"""
Burp Suite Wrapper
Web application security testing
"""

from typing import Dict, List, Any
from tools.base_wrapper import BaseToolWrapper


class BurpWrapper(BaseToolWrapper):
    """Burp Suite tool wrapper"""

    @property
    def tool_name(self) -> str:
        return 'burp'

    @property
    def description(self) -> str:
        return 'Web application security testing platform'

    @property
    def supported_actions(self) -> List[str]:
        return [
            'automated_scan',      # Automated vulnerability scan
            'crawl',               # Spider/crawl website
            'passive_scan',        # Passive scanning only
            'active_scan'          # Active scanning only
        ]

    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """Execute Burp Suite scan"""
        if not self.validate_target(target):
            raise ValueError(f'Invalid target: {target}')

        if action not in self.supported_actions:
            raise ValueError(f'Unsupported action: {action}')

        # Note: Burp Suite Community Edition doesn't have CLI automation
        # This wrapper would work with Burp Suite Professional + REST API
        # or use burp-rest-api (https://github.com/vmware/burp-rest-api)

        # For now, return placeholder indicating manual intervention needed
        self.logger.warning('Burp Suite integration requires Professional edition or REST API')

        return f"""Burp Suite scan queued for {target}
Action: {action}
Note: Burp Suite Community Edition requires manual operation.
Consider upgrading to Professional or using burp-rest-api for automation.

Options: {options}"""
