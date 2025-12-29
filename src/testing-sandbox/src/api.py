"""
Nexus-CyberAgent Testing Sandbox API
Orchestration server for security tool execution
"""

import asyncio
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from prometheus_client import Counter, Histogram, generate_latest
import redis.asyncio as redis

from tools.nmap_wrapper import NmapWrapper
from tools.nuclei_wrapper import NucleiWrapper
from tools.sqlmap_wrapper import SQLMapWrapper
from tools.nikto_wrapper import NiktoWrapper
from tools.burp_wrapper import BurpWrapper
from tools.hashcat_wrapper import HashcatWrapper
from tools.hydra_wrapper import HydraWrapper
from utils.logger import setup_logger
from utils.result_normalizer import ResultNormalizer

# Setup logging
logger = setup_logger('testing-sandbox')

# Prometheus metrics
tool_executions = Counter('tool_executions_total', 'Total tool executions', ['tool', 'status'])
tool_duration = Histogram('tool_duration_seconds', 'Tool execution duration', ['tool'])
api_requests = Counter('api_requests_total', 'Total API requests', ['endpoint', 'method', 'status'])

# Redis client for caching and result storage
redis_client: Optional[redis.Redis] = None

# Tool registry
TOOL_REGISTRY = {
    'nmap': NmapWrapper,
    'nuclei': NucleiWrapper,
    'sqlmap': SQLMapWrapper,
    'nikto': NiktoWrapper,
    'burp': BurpWrapper,
    'hashcat': HashcatWrapper,
    'hydra': HydraWrapper
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global redis_client

    # Startup
    logger.info('Starting Testing Sandbox API...')

    # Initialize Redis connection
    redis_host = os.getenv('REDIS_HOST', 'unified-brain-redis')
    redis_port = int(os.getenv('REDIS_PORT', 6379))
    redis_password = os.getenv('REDIS_PASSWORD', '')

    try:
        redis_client = await redis.from_url(
            f'redis://:{redis_password}@{redis_host}:{redis_port}/3',
            encoding='utf-8',
            decode_responses=True
        )
        await redis_client.ping()
        logger.info(f'Connected to Redis at {redis_host}:{redis_port}')
    except Exception as e:
        logger.error(f'Failed to connect to Redis: {e}')
        redis_client = None

    logger.info('Testing Sandbox API started successfully')

    yield

    # Shutdown
    logger.info('Shutting down Testing Sandbox API...')
    if redis_client:
        await redis_client.close()
    logger.info('Testing Sandbox API stopped')


# FastAPI app
app = FastAPI(
    title='Nexus-CyberAgent Testing Sandbox',
    description='Tier 2 security tool orchestration API',
    version='1.0.0',
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  # In production, restrict to API Gateway only
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)


# Request/Response models
class ToolExecutionRequest(BaseModel):
    """Tool execution request"""
    tool: str = Field(..., description='Tool name (e.g., nmap, nuclei, sqlmap)')
    target: str = Field(..., description='Target (IP, domain, URL, etc.)')
    action: str = Field(..., description='Tool-specific action (e.g., scan, exploit)')
    options: Optional[Dict[str, Any]] = Field(default_factory=dict, description='Tool-specific options')
    timeout: int = Field(default=3600, ge=1, le=7200, description='Execution timeout in seconds')

    @validator('tool')
    def validate_tool(cls, v):
        if v not in TOOL_REGISTRY:
            raise ValueError(f'Unsupported tool: {v}. Supported tools: {list(TOOL_REGISTRY.keys())}')
        return v


class ToolExecutionResponse(BaseModel):
    """Tool execution response"""
    execution_id: str = Field(..., description='Unique execution ID')
    tool: str
    target: str
    status: str = Field(..., description='Status: queued, running, completed, failed')
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    raw_output: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    available_tools: List[str]
    redis_connected: bool
    timestamp: datetime


# API endpoints
@app.get('/health', response_model=HealthResponse, tags=['System'])
async def health_check():
    """Health check endpoint"""
    api_requests.labels(endpoint='/health', method='GET', status='200').inc()

    redis_connected = False
    if redis_client:
        try:
            await redis_client.ping()
            redis_connected = True
        except Exception:
            pass

    return HealthResponse(
        status='healthy',
        version='1.0.0',
        available_tools=list(TOOL_REGISTRY.keys()),
        redis_connected=redis_connected,
        timestamp=datetime.utcnow()
    )


@app.get('/tools', tags=['Tools'])
async def list_tools():
    """List all available tools"""
    api_requests.labels(endpoint='/tools', method='GET', status='200').inc()

    tools = []
    for tool_name, tool_class in TOOL_REGISTRY.items():
        tool_instance = tool_class()
        tools.append({
            'name': tool_name,
            'description': tool_instance.description,
            'supported_actions': tool_instance.supported_actions,
            'version': await tool_instance.get_version()
        })

    return {'tools': tools}


@app.post('/execute', response_model=ToolExecutionResponse, tags=['Execution'])
async def execute_tool(
    request: ToolExecutionRequest,
    background_tasks: BackgroundTasks
):
    """
    Execute a security tool

    This endpoint queues the tool execution and returns immediately.
    Use GET /execution/{execution_id} to check status and retrieve results.
    """
    api_requests.labels(endpoint='/execute', method='POST', status='202').inc()

    execution_id = str(uuid.uuid4())

    # Create execution record
    execution_record = {
        'execution_id': execution_id,
        'tool': request.tool,
        'target': request.target,
        'action': request.action,
        'options': request.options,
        'status': 'queued',
        'started_at': datetime.utcnow().isoformat(),
        'completed_at': None,
        'duration_seconds': None,
        'results': None,
        'error': None
    }

    # Store in Redis
    if redis_client:
        await redis_client.setex(
            f'execution:{execution_id}',
            7200,  # 2 hours TTL
            str(execution_record)
        )

    # Queue execution in background
    background_tasks.add_task(
        run_tool_execution,
        execution_id,
        request.tool,
        request.target,
        request.action,
        request.options,
        request.timeout
    )

    logger.info(f'Queued tool execution: {execution_id} ({request.tool} -> {request.target})')

    return ToolExecutionResponse(
        execution_id=execution_id,
        tool=request.tool,
        target=request.target,
        status='queued',
        started_at=datetime.utcnow()
    )


@app.get('/execution/{execution_id}', response_model=ToolExecutionResponse, tags=['Execution'])
async def get_execution_status(execution_id: str):
    """Get execution status and results"""
    api_requests.labels(endpoint='/execution', method='GET', status='200').inc()

    if not redis_client:
        raise HTTPException(status_code=503, detail='Redis unavailable')

    # Retrieve from Redis
    execution_data = await redis_client.get(f'execution:{execution_id}')

    if not execution_data:
        raise HTTPException(status_code=404, detail='Execution not found')

    # Parse and return
    import json
    data = json.loads(execution_data.replace("'", '"'))

    return ToolExecutionResponse(**data)


@app.get('/metrics', tags=['System'])
async def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f'Unhandled exception: {exc}', exc_info=True)
    api_requests.labels(
        endpoint=request.url.path,
        method=request.method,
        status='500'
    ).inc()

    return JSONResponse(
        status_code=500,
        content={
            'error': 'Internal server error',
            'message': str(exc),
            'timestamp': datetime.utcnow().isoformat()
        }
    )


# Background task executor
async def run_tool_execution(
    execution_id: str,
    tool_name: str,
    target: str,
    action: str,
    options: Dict[str, Any],
    timeout: int
):
    """Execute tool in background"""
    start_time = datetime.utcnow()

    try:
        # Update status to running
        if redis_client:
            await redis_client.setex(
                f'execution:{execution_id}',
                7200,
                str({
                    'execution_id': execution_id,
                    'tool': tool_name,
                    'target': target,
                    'status': 'running',
                    'started_at': start_time.isoformat()
                })
            )

        # Get tool wrapper
        tool_class = TOOL_REGISTRY[tool_name]
        tool = tool_class()

        # Execute tool with timeout
        logger.info(f'Executing {tool_name} against {target} (action: {action})')

        with tool_duration.labels(tool=tool_name).time():
            raw_output = await asyncio.wait_for(
                tool.execute(target, action, options),
                timeout=timeout
            )

        # Normalize results
        normalizer = ResultNormalizer()
        results = normalizer.normalize(tool_name, raw_output)

        # Calculate duration
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Update status to completed
        execution_record = {
            'execution_id': execution_id,
            'tool': tool_name,
            'target': target,
            'status': 'completed',
            'started_at': start_time.isoformat(),
            'completed_at': end_time.isoformat(),
            'duration_seconds': duration,
            'results': results,
            'error': None,
            'raw_output': raw_output[:10000]  # Limit raw output size
        }

        if redis_client:
            await redis_client.setex(
                f'execution:{execution_id}',
                7200,
                str(execution_record)
            )

        tool_executions.labels(tool=tool_name, status='success').inc()
        logger.info(f'Tool execution completed: {execution_id} ({duration:.2f}s)')

    except asyncio.TimeoutError:
        error_msg = f'Tool execution timed out after {timeout} seconds'
        logger.error(f'{error_msg}: {execution_id}')

        if redis_client:
            await redis_client.setex(
                f'execution:{execution_id}',
                7200,
                str({
                    'execution_id': execution_id,
                    'tool': tool_name,
                    'target': target,
                    'status': 'failed',
                    'started_at': start_time.isoformat(),
                    'completed_at': datetime.utcnow().isoformat(),
                    'error': error_msg
                })
            )

        tool_executions.labels(tool=tool_name, status='timeout').inc()

    except Exception as e:
        error_msg = f'Tool execution failed: {str(e)}'
        logger.error(f'{error_msg}: {execution_id}', exc_info=True)

        if redis_client:
            await redis_client.setex(
                f'execution:{execution_id}',
                7200,
                str({
                    'execution_id': execution_id,
                    'tool': tool_name,
                    'target': target,
                    'status': 'failed',
                    'started_at': start_time.isoformat(),
                    'completed_at': datetime.utcnow().isoformat(),
                    'error': error_msg
                })
            )

        tool_executions.labels(tool=tool_name, status='error').inc()


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        app,
        host='0.0.0.0',
        port=9260,
        workers=4,
        log_level='info'
    )
