"""
Cuckoo Sandbox Client
Integration with Cuckoo Sandbox for automated malware analysis
"""

import asyncio
import os
from typing import Dict, List, Any, Optional
import aiohttp

from utils.logger import setup_logger

logger = setup_logger('cuckoo-client')


class CuckooClient:
    """Cuckoo Sandbox API client"""

    def __init__(self):
        self.api_url = os.getenv('CUCKOO_API_URL', 'http://localhost:8090')
        self.api_token = os.getenv('CUCKOO_API_TOKEN', '')
        self.timeout = int(os.getenv('CUCKOO_TIMEOUT', 600))

    async def check_status(self) -> bool:
        """Check if Cuckoo Sandbox is available"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'{self.api_url}/cuckoo/status', timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('status') == 'running'
            return False
        except Exception as e:
            logger.error(f'Cuckoo status check failed: {e}')
            return False

    async def get_vm_profiles(self) -> List[str]:
        """Get available VM profiles"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'{self.api_url}/machines/list', timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return [machine['name'] for machine in data.get('machines', [])]
            return ['win10', 'win11', 'ubuntu2204']  # Default profiles
        except Exception as e:
            logger.error(f'Failed to get VM profiles: {e}')
            return ['win10', 'win11', 'ubuntu2204']

    async def submit_sample(
        self,
        file_path: str,
        vm_profile: str = 'win10',
        timeout: int = 600,
        enable_network: bool = False,
        priority: int = 1
    ) -> int:
        """
        Submit malware sample to Cuckoo for analysis

        Args:
            file_path: Path to malware sample
            vm_profile: VM profile to use
            timeout: Analysis timeout in seconds
            enable_network: Enable network during analysis
            priority: Analysis priority (1-10)

        Returns:
            Cuckoo task ID
        """
        try:
            async with aiohttp.ClientSession() as session:
                with open(file_path, 'rb') as f:
                    data = aiohttp.FormData()
                    data.add_field('file', f, filename=os.path.basename(file_path))
                    data.add_field('machine', vm_profile)
                    data.add_field('timeout', str(timeout))
                    data.add_field('enforce_timeout', 'true')
                    data.add_field('memory', 'true')  # Enable memory dumping
                    data.add_field('priority', str(priority))

                    if enable_network:
                        data.add_field('network', 'true')
                        logger.warning('Network enabled for malware analysis - DANGEROUS!')

                    async with session.post(
                        f'{self.api_url}/tasks/create/file',
                        data=data,
                        timeout=30
                    ) as resp:
                        if resp.status == 200:
                            result = await resp.json()
                            task_id = result.get('task_id')

                            logger.info(f'Malware sample submitted to Cuckoo', extra={
                                'task_id': task_id,
                                'vm_profile': vm_profile,
                                'file_path': file_path
                            })

                            return task_id
                        else:
                            error = await resp.text()
                            raise Exception(f'Cuckoo submission failed: {error}')

        except Exception as e:
            logger.error(f'Failed to submit sample to Cuckoo: {e}', exc_info=True)
            raise

    async def get_task_status(self, task_id: int) -> str:
        """
        Get task status

        Returns:
            Status: pending, running, completed, reported, failed
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.api_url}/tasks/view/{task_id}',
                    timeout=10
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        task = data.get('task', {})
                        return task.get('status', 'unknown')
                    else:
                        return 'unknown'

        except Exception as e:
            logger.error(f'Failed to get task status: {e}')
            return 'unknown'

    async def wait_for_results(self, task_id: int, timeout: int = 660, poll_interval: int = 5) -> Dict[str, Any]:
        """
        Wait for Cuckoo analysis to complete and retrieve results

        Args:
            task_id: Cuckoo task ID
            timeout: Maximum wait time in seconds
            poll_interval: Polling interval in seconds

        Returns:
            Analysis results dictionary
        """
        start_time = asyncio.get_event_loop().time()

        logger.info(f'Waiting for Cuckoo analysis completion: task_id={task_id}')

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time

            if elapsed > timeout:
                raise TimeoutError(f'Cuckoo analysis timed out after {timeout} seconds')

            # Check status
            status = await self.get_task_status(task_id)

            logger.debug(f'Cuckoo task status: {status}', extra={'task_id': task_id})

            if status == 'reported':
                # Analysis complete, fetch results
                return await self.get_results(task_id)

            elif status == 'failed':
                raise Exception(f'Cuckoo analysis failed for task {task_id}')

            # Wait before next poll
            await asyncio.sleep(poll_interval)

    async def get_results(self, task_id: int) -> Dict[str, Any]:
        """
        Retrieve analysis results from Cuckoo

        Returns:
            Complete analysis results including:
            - Behavioral analysis
            - Network traffic
            - Dropped files
            - Memory dumps
            - Process tree
            - API calls
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.api_url}/tasks/report/{task_id}',
                    timeout=30
                ) as resp:
                    if resp.status == 200:
                        results = await resp.json()

                        logger.info(f'Retrieved Cuckoo results: task_id={task_id}', extra={
                            'signatures': len(results.get('signatures', [])),
                            'dropped_files': len(results.get('dropped', [])),
                            'network_events': len(results.get('network', {}).get('tcp', []))
                        })

                        # Extract key information
                        summary = {
                            'task_id': task_id,
                            'score': results.get('info', {}).get('score', 0),
                            'signatures': [
                                {
                                    'name': sig['name'],
                                    'severity': sig['severity'],
                                    'description': sig['description']
                                }
                                for sig in results.get('signatures', [])
                            ],
                            'network': {
                                'tcp': results.get('network', {}).get('tcp', []),
                                'udp': results.get('network', {}).get('udp', []),
                                'dns': results.get('network', {}).get('dns', []),
                                'http': results.get('network', {}).get('http', [])
                            },
                            'dropped_files': [
                                {
                                    'name': f['name'],
                                    'size': f['size'],
                                    'type': f['type'],
                                    'md5': f['md5'],
                                    'sha256': f['sha256']
                                }
                                for f in results.get('dropped', [])
                            ],
                            'processes': [
                                {
                                    'process_name': p['process_name'],
                                    'pid': p['process_id'],
                                    'command_line': p.get('command_line', ''),
                                    'first_seen': p.get('first_seen', '')
                                }
                                for p in results.get('behavior', {}).get('processes', [])
                            ],
                            'memory_dump': results.get('memory', {}).get('pslist', []),
                            'screenshots': results.get('screenshots', []),
                            'target': results.get('target', {})
                        }

                        return summary

                    else:
                        error = await resp.text()
                        raise Exception(f'Failed to retrieve results: {error}')

        except Exception as e:
            logger.error(f'Failed to retrieve Cuckoo results: {e}', exc_info=True)
            raise

    async def delete_task(self, task_id: int) -> bool:
        """Delete task and associated data"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.api_url}/tasks/delete/{task_id}',
                    timeout=10
                ) as resp:
                    return resp.status == 200

        except Exception as e:
            logger.error(f'Failed to delete task: {e}')
            return False
