"""
Base Tool Wrapper
Abstract base class for all security tool wrappers
"""

import asyncio
import subprocess
import shlex
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime

from utils.logger import setup_logger

logger = setup_logger('tool-wrapper')


class BaseToolWrapper(ABC):
    """Abstract base class for security tool wrappers"""

    def __init__(self):
        self.logger = setup_logger(f'tool-{self.tool_name}')

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Tool name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Tool description"""
        pass

    @property
    @abstractmethod
    def supported_actions(self) -> List[str]:
        """List of supported actions"""
        pass

    @abstractmethod
    async def execute(
        self,
        target: str,
        action: str,
        options: Dict[str, Any]
    ) -> str:
        """
        Execute the tool

        Args:
            target: Target (IP, domain, URL, etc.)
            action: Action to perform
            options: Tool-specific options

        Returns:
            Raw tool output as string
        """
        pass

    async def run_command(
        self,
        command: str,
        timeout: int = 3600,
        env: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Run shell command asynchronously

        Args:
            command: Command to execute
            timeout: Execution timeout in seconds
            env: Environment variables

        Returns:
            Command output

        Raises:
            subprocess.TimeoutExpired: If command times out
            subprocess.CalledProcessError: If command fails
        """
        self.logger.info(f'Executing command: {command[:200]}...')

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            output = stdout.decode('utf-8', errors='ignore')
            error = stderr.decode('utf-8', errors='ignore')

            if process.returncode != 0:
                self.logger.warning(f'Command failed with code {process.returncode}')
                self.logger.warning(f'stderr: {error[:500]}')

            # Return stdout + stderr combined
            return output + '\n' + error

        except asyncio.TimeoutError:
            self.logger.error(f'Command timed out after {timeout}s')
            raise
        except Exception as e:
            self.logger.error(f'Command execution failed: {e}')
            raise

    async def get_version(self) -> str:
        """Get tool version"""
        try:
            output = await self.run_command(f'{self.tool_name} --version', timeout=10)
            return output.split('\n')[0].strip()
        except Exception:
            return 'unknown'

    def validate_target(self, target: str) -> bool:
        """Validate target format (basic validation)"""
        if not target or len(target) == 0:
            return False
        # Add more validation as needed
        return True

    def build_command_args(self, **kwargs) -> List[str]:
        """Build command arguments from kwargs"""
        args = []
        for key, value in kwargs.items():
            if value is not None:
                if isinstance(value, bool):
                    if value:
                        args.append(f'--{key.replace("_", "-")}')
                elif isinstance(value, list):
                    for item in value:
                        args.append(f'--{key.replace("_", "-")}')
                        args.append(str(item))
                else:
                    args.append(f'--{key.replace("_", "-")}')
                    args.append(str(value))
        return args
