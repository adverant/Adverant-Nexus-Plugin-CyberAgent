"""
Nexus-CyberAgent Detonation Chamber API
Air-gapped malware analysis orchestration server
"""

import asyncio
import hashlib
import logging
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field, validator
from prometheus_client import Counter, Histogram, generate_latest
import redis.asyncio as redis

from tools.cuckoo_client import CuckooClient
from tools.volatility_analyzer import VolatilityAnalyzer
from tools.yara_scanner import YaraScanner
from tools.ioc_extractor import IOCExtractor
from tools.static_analyzer import StaticAnalyzer
from utils.logger import setup_logger
from utils.result_aggregator import ResultAggregator

# Setup logging
logger = setup_logger('detonation-chamber')

# Prometheus metrics
analysis_counter = Counter('malware_analyses_total', 'Total malware analyses', ['status'])
analysis_duration = Histogram('malware_analysis_duration_seconds', 'Malware analysis duration')
api_requests = Counter('api_requests_total', 'Total API requests', ['endpoint', 'method', 'status'])

# Redis client
redis_client: Optional[redis.Redis] = None

# Tool instances
cuckoo_client: Optional[CuckooClient] = None
volatility_analyzer: Optional[VolatilityAnalyzer] = None
yara_scanner: Optional[YaraScanner] = None
ioc_extractor: Optional[IOCExtractor] = None
static_analyzer: Optional[StaticAnalyzer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global redis_client, cuckoo_client, volatility_analyzer, yara_scanner, ioc_extractor, static_analyzer

    # Startup
    logger.info('Starting Detonation Chamber API...')

    # Initialize Redis connection
    redis_host = os.getenv('REDIS_HOST', 'unified-brain-redis')
    redis_port = int(os.getenv('REDIS_PORT', 6379))
    redis_password = os.getenv('REDIS_PASSWORD', '')

    try:
        redis_client = await redis.from_url(
            f'redis://:{redis_password}@{redis_host}:{redis_port}/4',
            encoding='utf-8',
            decode_responses=True
        )
        await redis_client.ping()
        logger.info(f'Connected to Redis at {redis_host}:{redis_port}')
    except Exception as e:
        logger.error(f'Failed to connect to Redis: {e}')
        redis_client = None

    # Initialize analysis tools
    try:
        cuckoo_client = CuckooClient()
        volatility_analyzer = VolatilityAnalyzer()
        yara_scanner = YaraScanner()
        ioc_extractor = IOCExtractor()
        static_analyzer = StaticAnalyzer()
        logger.info('Analysis tools initialized successfully')
    except Exception as e:
        logger.error(f'Failed to initialize analysis tools: {e}')

    logger.info('Detonation Chamber API started successfully')

    yield

    # Shutdown
    logger.info('Shutting down Detonation Chamber API...')
    if redis_client:
        await redis_client.close()
    logger.info('Detonation Chamber API stopped')


# FastAPI app
app = FastAPI(
    title='Nexus-CyberAgent Detonation Chamber',
    description='Tier 3 air-gapped malware analysis API',
    version='1.0.0',
    lifespan=lifespan
)

# CORS middleware (restrict to API Gateway only in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)


# Request/Response models
class MalwareSubmissionRequest(BaseModel):
    """Malware submission request"""
    filename: str = Field(..., description='Original filename')
    sha256: Optional[str] = Field(None, description='SHA256 hash (optional, will be computed)')
    analysis_timeout: int = Field(default=600, ge=60, le=3600, description='Analysis timeout in seconds')
    vm_profile: str = Field(default='win10', description='VM profile (win10, win11, ubuntu2204)')
    enable_network: bool = Field(default=False, description='Enable network during analysis (DANGEROUS)')
    priority: int = Field(default=1, ge=1, le=10, description='Analysis priority')

    @validator('vm_profile')
    def validate_vm_profile(cls, v):
        allowed = ['win10', 'win11', 'ubuntu2204']
        if v not in allowed:
            raise ValueError(f'Invalid VM profile. Allowed: {allowed}')
        return v


class AnalysisResponse(BaseModel):
    """Analysis response"""
    analysis_id: str = Field(..., description='Unique analysis ID')
    sha256: str
    status: str = Field(..., description='Status: queued, analyzing, completed, failed')
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    vm_profile: str
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    cuckoo_available: bool
    vm_profiles_available: List[str]
    redis_connected: bool
    timestamp: datetime


class IOCResponse(BaseModel):
    """IOC extraction response"""
    analysis_id: str
    iocs: Dict[str, List[str]] = Field(..., description='IOCs by type (ip, domain, url, hash, registry, mutex)')
    confidence_scores: Dict[str, float]
    yara_matches: List[str]
    malware_family: Optional[str]
    threat_level: str


# ============================================================================
# Decompilation Models
# ============================================================================

class DecompileRadare2Request(BaseModel):
    """Radare2 decompilation request"""
    file_path: str = Field(..., description='Path to binary file')
    extract_functions: bool = Field(default=True, description='Extract function list')
    extract_strings: bool = Field(default=True, description='Extract string references')
    extract_xrefs: bool = Field(default=False, description='Extract cross-references')
    max_functions: int = Field(default=100, ge=1, le=500, description='Maximum functions to analyze')
    target_functions: Optional[List[str]] = Field(default=None, description='Specific function addresses to analyze')
    timeout: int = Field(default=120, ge=30, le=600, description='Timeout in seconds')


class DecompileGhidraRequest(BaseModel):
    """Ghidra decompilation request"""
    file_path: str = Field(..., description='Path to binary file')
    extract_functions: bool = Field(default=True, description='Extract function list')
    extract_strings: bool = Field(default=True, description='Extract string references')
    extract_xrefs: bool = Field(default=True, description='Extract cross-references')
    max_functions: int = Field(default=50, ge=1, le=200, description='Maximum functions to analyze')
    target_functions: Optional[List[str]] = Field(default=None, description='Specific function addresses to analyze')
    timeout: int = Field(default=300, ge=60, le=1800, description='Timeout in seconds')


class ExtractedFunctionResponse(BaseModel):
    """Extracted function information"""
    name: str
    address: str
    size: int
    disassembly: Optional[str] = None
    pseudocode: Optional[str] = None
    calling_convention: Optional[str] = None
    argc: Optional[int] = None
    return_type: Optional[str] = None
    callees: Optional[List[str]] = None
    callers: Optional[List[str]] = None
    string_refs: Optional[List[str]] = None
    cyclomatic_complexity: Optional[int] = None


class DecompilationResponse(BaseModel):
    """Decompilation response"""
    success: bool
    error: Optional[str] = None
    tool: str
    tool_version: Optional[str] = None
    total_functions: int
    architecture: Optional[str] = None
    format: Optional[str] = None
    entry_point: Optional[str] = None
    functions: List[ExtractedFunctionResponse]
    strings: Optional[List[Dict[str, Any]]] = None
    imports: Optional[List[Dict[str, str]]] = None
    exports: Optional[List[Dict[str, Any]]] = None


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

    cuckoo_available = False
    vm_profiles = []
    if cuckoo_client:
        try:
            cuckoo_available = await cuckoo_client.check_status()
            vm_profiles = await cuckoo_client.get_vm_profiles()
        except Exception:
            pass

    return HealthResponse(
        status='healthy',
        version='1.0.0',
        cuckoo_available=cuckoo_available,
        vm_profiles_available=vm_profiles,
        redis_connected=redis_connected,
        timestamp=datetime.utcnow()
    )


@app.post('/upload', tags=['Malware'])
async def upload_malware(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """
    Upload malware sample for analysis

    Returns analysis_id for tracking
    """
    api_requests.labels(endpoint='/upload', method='POST', status='202').inc()

    try:
        # Read file content
        content = await file.read()

        # Compute hashes
        sha256_hash = hashlib.sha256(content).hexdigest()
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()

        # Save to malware storage
        malware_path = Path(os.getenv('MALWARE_PATH', '/app/malware'))
        malware_path.mkdir(parents=True, exist_ok=True)

        sample_file = malware_path / sha256_hash
        with open(sample_file, 'wb') as f:
            f.write(content)

        # Create analysis record
        analysis_id = str(uuid.uuid4())

        analysis_record = {
            'analysis_id': analysis_id,
            'sha256': sha256_hash,
            'md5': md5_hash,
            'sha1': sha1_hash,
            'filename': file.filename,
            'file_size': len(content),
            'status': 'queued',
            'submitted_at': datetime.utcnow().isoformat(),
            'completed_at': None,
            'vm_profile': 'win10',
            'results': None
        }

        # Store in Redis
        if redis_client:
            await redis_client.setex(
                f'analysis:{analysis_id}',
                86400,  # 24 hours TTL
                str(analysis_record)
            )

        logger.info(f'Malware sample uploaded: {sha256_hash}', extra={
            'analysis_id': analysis_id,
            'filename': file.filename,
            'size': len(content)
        })

        return {
            'analysis_id': analysis_id,
            'sha256': sha256_hash,
            'md5': md5_hash,
            'sha1': sha1_hash,
            'status': 'queued',
            'message': 'Sample uploaded successfully. Use /analyze to start analysis.'
        }

    except Exception as e:
        logger.error(f'Failed to upload malware sample: {e}', exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/analyze/{analysis_id}', response_model=AnalysisResponse, tags=['Analysis'])
async def analyze_malware(
    analysis_id: str,
    request: MalwareSubmissionRequest,
    background_tasks: BackgroundTasks
):
    """
    Start malware analysis

    Performs comprehensive analysis including:
    - Static analysis (PE/ELF parsing, strings extraction)
    - YARA scanning
    - Cuckoo Sandbox behavioral analysis
    - Memory forensics (Volatility)
    - Network analysis
    - IOC extraction
    """
    api_requests.labels(endpoint='/analyze', method='POST', status='202').inc()

    # Queue analysis in background
    background_tasks.add_task(
        run_malware_analysis,
        analysis_id,
        request.sha256,
        request.vm_profile,
        request.analysis_timeout,
        request.enable_network,
        request.priority
    )

    logger.info(f'Malware analysis queued: {analysis_id}')

    return AnalysisResponse(
        analysis_id=analysis_id,
        sha256=request.sha256 or 'unknown',
        status='analyzing',
        submitted_at=datetime.utcnow(),
        vm_profile=request.vm_profile
    )


@app.get('/analysis/{analysis_id}', response_model=AnalysisResponse, tags=['Analysis'])
async def get_analysis_status(analysis_id: str):
    """Get analysis status and results"""
    api_requests.labels(endpoint='/analysis', method='GET', status='200').inc()

    if not redis_client:
        raise HTTPException(status_code=503, detail='Redis unavailable')

    # Retrieve from Redis
    analysis_data = await redis_client.get(f'analysis:{analysis_id}')

    if not analysis_data:
        raise HTTPException(status_code=404, detail='Analysis not found')

    # Parse and return
    import json
    data = json.loads(analysis_data.replace("'", '"'))

    return AnalysisResponse(**data)


@app.get('/iocs/{analysis_id}', response_model=IOCResponse, tags=['IOCs'])
async def get_iocs(analysis_id: str):
    """Extract IOCs from analysis results"""
    api_requests.labels(endpoint='/iocs', method='GET', status='200').inc()

    # Get analysis results
    if not redis_client:
        raise HTTPException(status_code=503, detail='Redis unavailable')

    analysis_data = await redis_client.get(f'analysis:{analysis_id}')
    if not analysis_data:
        raise HTTPException(status_code=404, detail='Analysis not found')

    import json
    data = json.loads(analysis_data.replace("'", '"'))

    if not data.get('results'):
        raise HTTPException(status_code=400, detail='Analysis not completed')

    # Extract IOCs
    iocs = ioc_extractor.extract_iocs(data['results'])

    return IOCResponse(
        analysis_id=analysis_id,
        iocs=iocs['iocs'],
        confidence_scores=iocs['confidence_scores'],
        yara_matches=iocs['yara_matches'],
        malware_family=iocs.get('malware_family'),
        threat_level=iocs.get('threat_level', 'unknown')
    )


@app.get('/download/report/{analysis_id}', tags=['Reports'])
async def download_report(analysis_id: str, format: str = 'json'):
    """Download analysis report"""
    api_requests.labels(endpoint='/download/report', method='GET', status='200').inc()

    if not redis_client:
        raise HTTPException(status_code=503, detail='Redis unavailable')

    analysis_data = await redis_client.get(f'analysis:{analysis_id}')
    if not analysis_data:
        raise HTTPException(status_code=404, detail='Analysis not found')

    # Generate report
    results_path = Path(os.getenv('RESULTS_PATH', '/app/results'))
    report_file = results_path / f'{analysis_id}_report.{format}'

    if not report_file.exists():
        raise HTTPException(status_code=404, detail='Report not found')

    return FileResponse(
        path=str(report_file),
        filename=f'malware_analysis_{analysis_id}.{format}',
        media_type='application/json' if format == 'json' else 'application/pdf'
    )


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
async def run_malware_analysis(
    analysis_id: str,
    sha256: str,
    vm_profile: str,
    timeout: int,
    enable_network: bool,
    priority: int
):
    """Execute comprehensive malware analysis"""
    start_time = datetime.utcnow()

    try:
        logger.info(f'Starting malware analysis: {analysis_id}', extra={
            'sha256': sha256,
            'vm_profile': vm_profile
        })

        # Update status to analyzing
        if redis_client:
            await redis_client.setex(
                f'analysis:{analysis_id}',
                86400,
                str({
                    'analysis_id': analysis_id,
                    'sha256': sha256,
                    'status': 'analyzing',
                    'submitted_at': start_time.isoformat()
                })
            )

        results = {}

        # Phase 1: Static Analysis
        logger.info(f'Phase 1: Static analysis - {analysis_id}')
        malware_path = Path(os.getenv('MALWARE_PATH', '/app/malware')) / sha256

        if static_analyzer:
            results['static_analysis'] = await static_analyzer.analyze(str(malware_path))

        # Phase 2: YARA Scanning
        logger.info(f'Phase 2: YARA scanning - {analysis_id}')
        if yara_scanner:
            results['yara_matches'] = await yara_scanner.scan(str(malware_path))

        # Phase 3: Cuckoo Sandbox Analysis
        logger.info(f'Phase 3: Cuckoo Sandbox analysis - {analysis_id}')
        if cuckoo_client:
            cuckoo_task_id = await cuckoo_client.submit_sample(
                str(malware_path),
                vm_profile=vm_profile,
                timeout=timeout,
                enable_network=enable_network,
                priority=priority
            )

            results['cuckoo_task_id'] = cuckoo_task_id

            # Wait for Cuckoo analysis to complete
            cuckoo_results = await cuckoo_client.wait_for_results(cuckoo_task_id, timeout=timeout + 60)
            results['behavioral_analysis'] = cuckoo_results

        # Phase 4: Memory Forensics (if memory dump available)
        logger.info(f'Phase 4: Memory forensics - {analysis_id}')
        if volatility_analyzer and results.get('behavioral_analysis', {}).get('memory_dump'):
            memory_dump = results['behavioral_analysis']['memory_dump']
            results['memory_analysis'] = await volatility_analyzer.analyze(memory_dump)

        # Phase 5: IOC Extraction
        logger.info(f'Phase 5: IOC extraction - {analysis_id}')
        if ioc_extractor:
            results['iocs'] = ioc_extractor.extract_iocs(results)

        # Aggregate results
        aggregator = ResultAggregator()
        final_results = aggregator.aggregate(results)

        # Calculate duration
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Update status to completed
        analysis_record = {
            'analysis_id': analysis_id,
            'sha256': sha256,
            'status': 'completed',
            'submitted_at': start_time.isoformat(),
            'completed_at': end_time.isoformat(),
            'duration_seconds': duration,
            'vm_profile': vm_profile,
            'results': final_results,
            'error': None
        }

        if redis_client:
            await redis_client.setex(
                f'analysis:{analysis_id}',
                86400,
                str(analysis_record)
            )

        analysis_counter.labels(status='success').inc()
        logger.info(f'Malware analysis completed: {analysis_id}', extra={'duration': duration})

    except Exception as e:
        error_msg = f'Malware analysis failed: {str(e)}'
        logger.error(error_msg, exc_info=True, extra={'analysis_id': analysis_id})

        if redis_client:
            await redis_client.setex(
                f'analysis:{analysis_id}',
                86400,
                str({
                    'analysis_id': analysis_id,
                    'sha256': sha256,
                    'status': 'failed',
                    'submitted_at': start_time.isoformat(),
                    'completed_at': datetime.utcnow().isoformat(),
                    'error': error_msg
                })
            )

        analysis_counter.labels(status='error').inc()


# ============================================================================
# Decompilation Endpoints
# ============================================================================

# Prometheus metrics for decompilation
decompile_counter = Counter('decompilation_total', 'Total decompilation requests', ['tool', 'status'])
decompile_duration = Histogram('decompilation_duration_seconds', 'Decompilation duration', ['tool'])


@app.post('/decompile/radare2', response_model=DecompilationResponse, tags=['Decompilation'])
async def decompile_radare2(request: DecompileRadare2Request):
    """
    Quick disassembly using Radare2 (r2)

    Provides fast function extraction and disassembly without full decompilation.
    Best for:
    - Quick triage of suspicious binaries
    - Function enumeration
    - Basic control flow analysis
    """
    api_requests.labels(endpoint='/decompile/radare2', method='POST', status='200').inc()
    start_time = datetime.utcnow()

    try:
        logger.info(f'Starting Radare2 decompilation: {request.file_path}', extra={
            'max_functions': request.max_functions,
            'extract_strings': request.extract_strings
        })

        # Verify file exists
        file_path = Path(request.file_path)
        if not file_path.exists():
            # Check in malware storage
            malware_path = Path(os.getenv('MALWARE_PATH', '/app/malware'))
            file_path = malware_path / request.file_path
            if not file_path.exists():
                raise HTTPException(status_code=404, detail=f'File not found: {request.file_path}')

        result = await run_radare2_analysis(
            str(file_path),
            extract_functions=request.extract_functions,
            extract_strings=request.extract_strings,
            extract_xrefs=request.extract_xrefs,
            max_functions=request.max_functions,
            target_functions=request.target_functions,
            timeout=request.timeout
        )

        duration = (datetime.utcnow() - start_time).total_seconds()
        decompile_counter.labels(tool='radare2', status='success').inc()
        decompile_duration.labels(tool='radare2').observe(duration)

        logger.info(f'Radare2 decompilation completed', extra={
            'file_path': str(file_path),
            'functions_found': result.get('total_functions', 0),
            'duration_seconds': duration
        })

        return DecompilationResponse(
            success=True,
            tool='radare2',
            tool_version=result.get('tool_version'),
            total_functions=result.get('total_functions', 0),
            architecture=result.get('architecture'),
            format=result.get('format'),
            entry_point=result.get('entry_point'),
            functions=result.get('functions', []),
            strings=result.get('strings'),
            imports=result.get('imports'),
            exports=result.get('exports')
        )

    except HTTPException:
        raise
    except asyncio.TimeoutError:
        decompile_counter.labels(tool='radare2', status='timeout').inc()
        logger.error(f'Radare2 decompilation timeout: {request.file_path}')
        raise HTTPException(status_code=504, detail='Decompilation timeout')
    except Exception as e:
        decompile_counter.labels(tool='radare2', status='error').inc()
        logger.error(f'Radare2 decompilation failed: {e}', exc_info=True)
        return DecompilationResponse(
            success=False,
            error=str(e),
            tool='radare2',
            total_functions=0,
            functions=[]
        )


@app.post('/decompile/ghidra', response_model=DecompilationResponse, tags=['Decompilation'])
async def decompile_ghidra(request: DecompileGhidraRequest):
    """
    Full decompilation using Ghidra headless analyzer

    Provides high-quality pseudocode decompilation with full analysis.
    Best for:
    - Deep analysis of malware
    - Pseudocode generation for understanding logic
    - Complete cross-reference analysis
    - High/critical threat samples

    Note: Slower than Radare2 but provides much more detailed output.
    """
    api_requests.labels(endpoint='/decompile/ghidra', method='POST', status='200').inc()
    start_time = datetime.utcnow()

    try:
        logger.info(f'Starting Ghidra decompilation: {request.file_path}', extra={
            'max_functions': request.max_functions,
            'extract_xrefs': request.extract_xrefs
        })

        # Verify file exists
        file_path = Path(request.file_path)
        if not file_path.exists():
            # Check in malware storage
            malware_path = Path(os.getenv('MALWARE_PATH', '/app/malware'))
            file_path = malware_path / request.file_path
            if not file_path.exists():
                raise HTTPException(status_code=404, detail=f'File not found: {request.file_path}')

        result = await run_ghidra_analysis(
            str(file_path),
            extract_functions=request.extract_functions,
            extract_strings=request.extract_strings,
            extract_xrefs=request.extract_xrefs,
            max_functions=request.max_functions,
            target_functions=request.target_functions,
            timeout=request.timeout
        )

        duration = (datetime.utcnow() - start_time).total_seconds()
        decompile_counter.labels(tool='ghidra', status='success').inc()
        decompile_duration.labels(tool='ghidra').observe(duration)

        logger.info(f'Ghidra decompilation completed', extra={
            'file_path': str(file_path),
            'functions_found': result.get('total_functions', 0),
            'duration_seconds': duration
        })

        return DecompilationResponse(
            success=True,
            tool='ghidra',
            tool_version=result.get('tool_version'),
            total_functions=result.get('total_functions', 0),
            architecture=result.get('architecture'),
            format=result.get('format'),
            entry_point=result.get('entry_point'),
            functions=result.get('functions', []),
            strings=result.get('strings'),
            imports=result.get('imports'),
            exports=result.get('exports')
        )

    except HTTPException:
        raise
    except asyncio.TimeoutError:
        decompile_counter.labels(tool='ghidra', status='timeout').inc()
        logger.error(f'Ghidra decompilation timeout: {request.file_path}')
        raise HTTPException(status_code=504, detail='Decompilation timeout')
    except Exception as e:
        decompile_counter.labels(tool='ghidra', status='error').inc()
        logger.error(f'Ghidra decompilation failed: {e}', exc_info=True)
        return DecompilationResponse(
            success=False,
            error=str(e),
            tool='ghidra',
            total_functions=0,
            functions=[]
        )


async def run_radare2_analysis(
    file_path: str,
    extract_functions: bool = True,
    extract_strings: bool = True,
    extract_xrefs: bool = False,
    max_functions: int = 100,
    target_functions: Optional[List[str]] = None,
    timeout: int = 120
) -> Dict[str, Any]:
    """
    Run Radare2 analysis on a binary file

    Uses r2pipe for programmatic access to Radare2.
    """
    import json

    result = {
        'tool_version': None,
        'total_functions': 0,
        'architecture': None,
        'format': None,
        'entry_point': None,
        'functions': [],
        'strings': [],
        'imports': [],
        'exports': []
    }

    try:
        # Try to use r2pipe if available
        import r2pipe

        logger.debug(f'Opening file with r2pipe: {file_path}')
        r2 = r2pipe.open(file_path, flags=['-2'])  # -2 disables stderr

        try:
            # Get version
            version_info = r2.cmdj('?V')
            result['tool_version'] = version_info if isinstance(version_info, str) else str(version_info)

            # Analyze binary
            r2.cmd('aaa')  # Analyze all (faster than aaaa)

            # Get binary info
            info = r2.cmdj('ij')
            if info and 'bin' in info:
                bin_info = info['bin']
                result['architecture'] = bin_info.get('arch', 'unknown')
                result['format'] = bin_info.get('bintype', 'unknown')
                result['entry_point'] = hex(info.get('core', {}).get('vaddr', 0)) if info.get('core') else None

            # Get functions
            if extract_functions:
                functions = r2.cmdj('aflj') or []
                result['total_functions'] = len(functions)

                # Limit functions
                funcs_to_analyze = functions[:max_functions]
                if target_functions:
                    funcs_to_analyze = [f for f in functions if f.get('offset') and
                                        hex(f['offset']) in target_functions]

                for func in funcs_to_analyze:
                    func_addr = hex(func.get('offset', 0))
                    func_name = func.get('name', f'sub_{func_addr}')
                    func_size = func.get('size', 0)

                    # Get disassembly
                    disasm = ''
                    try:
                        r2.cmd(f's {func_addr}')
                        disasm_lines = r2.cmd(f'pdf')
                        disasm = disasm_lines if disasm_lines else ''
                    except Exception:
                        pass

                    # Get callees (functions this function calls)
                    callees = []
                    try:
                        xrefs = r2.cmdj(f'axtj @ {func_addr}') or []
                        callees = list(set([hex(x.get('to', 0)) for x in xrefs if x.get('type') == 'CALL']))
                    except Exception:
                        pass

                    # Get string references in function
                    string_refs = []
                    if extract_strings:
                        try:
                            # Get strings referenced in this function range
                            r2.cmd(f's {func_addr}')
                            str_refs = r2.cmdj(f'pdsj {func_size}') or []
                            string_refs = [s.get('string', '') for s in str_refs
                                           if s.get('type') == 'string' and s.get('string')][:20]
                        except Exception:
                            pass

                    result['functions'].append({
                        'name': func_name,
                        'address': func_addr,
                        'size': func_size,
                        'disassembly': disasm[:10000],  # Limit size
                        'argc': func.get('nargs', 0),
                        'callees': callees[:50],
                        'string_refs': string_refs,
                        'cyclomatic_complexity': func.get('cc', 1)
                    })

            # Get all strings
            if extract_strings:
                try:
                    strings = r2.cmdj('izj') or []
                    result['strings'] = [
                        {
                            'value': s.get('string', ''),
                            'address': hex(s.get('vaddr', 0)),
                            'type': s.get('type', 'ascii')
                        }
                        for s in strings[:500]  # Limit
                    ]
                except Exception:
                    pass

            # Get imports
            try:
                imports = r2.cmdj('iij') or []
                result['imports'] = [
                    {
                        'library': i.get('libname', ''),
                        'function': i.get('name', ''),
                        'address': hex(i.get('plt', 0))
                    }
                    for i in imports
                ]
            except Exception:
                pass

            # Get exports
            try:
                exports = r2.cmdj('iEj') or []
                result['exports'] = [
                    {
                        'name': e.get('name', ''),
                        'address': hex(e.get('vaddr', 0))
                    }
                    for e in exports
                ]
            except Exception:
                pass

        finally:
            r2.quit()

    except ImportError:
        # Fallback to command line r2
        logger.warning('r2pipe not available, using command line fallback')
        result = await run_radare2_cli(file_path, extract_functions, extract_strings, timeout)

    return result


async def run_radare2_cli(
    file_path: str,
    extract_functions: bool,
    extract_strings: bool,
    timeout: int
) -> Dict[str, Any]:
    """
    Fallback: Run Radare2 via command line
    """
    import json

    result = {
        'tool_version': 'cli',
        'total_functions': 0,
        'architecture': None,
        'format': None,
        'entry_point': None,
        'functions': [],
        'strings': [],
        'imports': [],
        'exports': []
    }

    # Build r2 commands
    commands = [
        'aaa',  # Analyze
        'ij',   # Info JSON
        'aflj', # Functions JSON
    ]
    if extract_strings:
        commands.append('izj')

    r2_script = ';'.join(commands)

    try:
        proc = await asyncio.create_subprocess_exec(
            'r2', '-q', '-c', r2_script, '-', file_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode('utf-8', errors='ignore')

        # Parse JSON outputs (they come separated by newlines)
        parts = output.strip().split('\n')
        for part in parts:
            try:
                data = json.loads(part)
                if isinstance(data, dict) and 'bin' in data:
                    result['architecture'] = data['bin'].get('arch')
                    result['format'] = data['bin'].get('bintype')
                elif isinstance(data, list) and len(data) > 0:
                    if 'offset' in data[0] and 'name' in data[0]:
                        # Functions
                        result['total_functions'] = len(data)
                        result['functions'] = [
                            {
                                'name': f.get('name', ''),
                                'address': hex(f.get('offset', 0)),
                                'size': f.get('size', 0),
                                'argc': f.get('nargs', 0)
                            }
                            for f in data[:100]
                        ]
                    elif 'string' in data[0]:
                        # Strings
                        result['strings'] = [
                            {
                                'value': s.get('string', ''),
                                'address': hex(s.get('vaddr', 0))
                            }
                            for s in data[:500]
                        ]
            except json.JSONDecodeError:
                continue

    except asyncio.TimeoutError:
        raise
    except Exception as e:
        logger.error(f'Radare2 CLI execution failed: {e}')
        raise

    return result


async def run_ghidra_analysis(
    file_path: str,
    extract_functions: bool = True,
    extract_strings: bool = True,
    extract_xrefs: bool = True,
    max_functions: int = 50,
    target_functions: Optional[List[str]] = None,
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Run Ghidra headless analysis on a binary file

    Uses Ghidra's analyzeHeadless command with a custom script.
    """
    import json

    result = {
        'tool_version': None,
        'total_functions': 0,
        'architecture': None,
        'format': None,
        'entry_point': None,
        'functions': [],
        'strings': [],
        'imports': [],
        'exports': []
    }

    ghidra_home = os.getenv('GHIDRA_HOME', '/opt/ghidra')
    ghidra_headless = f'{ghidra_home}/support/analyzeHeadless'

    if not os.path.exists(ghidra_headless):
        raise Exception(f'Ghidra headless analyzer not found at {ghidra_headless}')

    # Create temporary project directory and output file
    with tempfile.TemporaryDirectory() as temp_dir:
        project_dir = Path(temp_dir) / 'ghidra_project'
        project_dir.mkdir()
        output_file = Path(temp_dir) / 'output.json'

        # Create analysis script
        script_content = create_ghidra_analysis_script(
            str(output_file),
            extract_functions=extract_functions,
            extract_strings=extract_strings,
            extract_xrefs=extract_xrefs,
            max_functions=max_functions,
            target_functions=target_functions
        )

        script_file = Path(temp_dir) / 'analyze.py'
        with open(script_file, 'w') as f:
            f.write(script_content)

        # Run Ghidra headless
        cmd = [
            ghidra_headless,
            str(project_dir),
            'TempProject',
            '-import', file_path,
            '-postScript', str(script_file),
            '-scriptPath', temp_dir,
            '-deleteProject'  # Clean up project after
        ]

        logger.debug(f'Running Ghidra: {" ".join(cmd)}')

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            if proc.returncode != 0:
                error_output = stderr.decode('utf-8', errors='ignore')
                logger.error(f'Ghidra analysis failed: {error_output}')
                raise Exception(f'Ghidra analysis failed with code {proc.returncode}')

            # Read output file
            if output_file.exists():
                with open(output_file, 'r') as f:
                    result = json.load(f)
                    result['tool'] = 'ghidra'
            else:
                logger.warning('Ghidra output file not created')

        except asyncio.TimeoutError:
            raise
        except Exception as e:
            logger.error(f'Ghidra execution failed: {e}', exc_info=True)
            raise

    return result


def create_ghidra_analysis_script(
    output_file: str,
    extract_functions: bool,
    extract_strings: bool,
    extract_xrefs: bool,
    max_functions: int,
    target_functions: Optional[List[str]]
) -> str:
    """
    Create a Ghidra Python analysis script

    This script runs inside Ghidra's Jython environment.
    """
    target_addrs = json.dumps(target_functions) if target_functions else 'None'

    return f'''# Ghidra Decompilation Script
# Auto-generated by Nexus-CyberAgent Detonation Chamber

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

OUTPUT_FILE = "{output_file}"
MAX_FUNCTIONS = {max_functions}
EXTRACT_FUNCTIONS = {str(extract_functions)}
EXTRACT_STRINGS = {str(extract_strings)}
EXTRACT_XREFS = {str(extract_xrefs)}
TARGET_FUNCTIONS = {target_addrs}

def main():
    result = {{
        'tool_version': 'ghidra',
        'total_functions': 0,
        'architecture': None,
        'format': None,
        'entry_point': None,
        'functions': [],
        'strings': [],
        'imports': [],
        'exports': []
    }}

    try:
        program = currentProgram
        listing = program.getListing()
        memory = program.getMemory()

        # Get program info
        lang = program.getLanguage()
        result['architecture'] = str(lang.getProcessor())
        result['format'] = str(program.getExecutableFormat())

        # Get entry point
        entry_points = program.getSymbolTable().getExternalEntryPointIterator()
        for ep in entry_points:
            result['entry_point'] = str(ep)
            break

        # Initialize decompiler
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        monitor = ConsoleTaskMonitor()

        # Get functions
        if EXTRACT_FUNCTIONS:
            func_manager = program.getFunctionManager()
            functions = list(func_manager.getFunctions(True))
            result['total_functions'] = len(functions)

            # Filter to target functions if specified
            if TARGET_FUNCTIONS:
                functions = [f for f in functions if str(f.getEntryPoint()) in TARGET_FUNCTIONS]

            # Limit functions
            functions = functions[:MAX_FUNCTIONS]

            for func in functions:
                try:
                    func_entry = func.getEntryPoint()
                    func_name = func.getName()
                    func_size = func.getBody().getNumAddresses()

                    # Decompile function
                    pseudocode = ""
                    try:
                        results = decompiler.decompileFunction(func, 30, monitor)
                        if results and results.decompileCompleted():
                            decomp = results.getDecompiledFunction()
                            if decomp:
                                pseudocode = decomp.getC()
                    except:
                        pass

                    # Get callees
                    callees = []
                    if EXTRACT_XREFS:
                        for called in func.getCalledFunctions(monitor):
                            callees.append(str(called.getEntryPoint()))

                    # Get callers
                    callers = []
                    if EXTRACT_XREFS:
                        for caller in func.getCallingFunctions(monitor):
                            callers.append(str(caller.getEntryPoint()))

                    # Get string references
                    string_refs = []
                    if EXTRACT_STRINGS:
                        refs = program.getReferenceManager().getReferencesFrom(func_entry)
                        for ref in refs:
                            to_addr = ref.getToAddress()
                            data = listing.getDataAt(to_addr)
                            if data and data.hasStringValue():
                                string_refs.append(str(data.getValue()))

                    result['functions'].append({{
                        'name': func_name,
                        'address': str(func_entry),
                        'size': func_size,
                        'pseudocode': pseudocode[:10000] if pseudocode else None,
                        'return_type': str(func.getReturnType()),
                        'argc': func.getParameterCount(),
                        'calling_convention': str(func.getCallingConventionName()),
                        'callees': callees[:50],
                        'callers': callers[:50],
                        'string_refs': string_refs[:20]
                    }})
                except Exception as e:
                    continue

        # Get all strings
        if EXTRACT_STRINGS:
            for data in listing.getDefinedData(True):
                if data.hasStringValue():
                    result['strings'].append({{
                        'value': str(data.getValue()),
                        'address': str(data.getAddress())
                    }})
                    if len(result['strings']) >= 500:
                        break

        # Get imports
        symbol_table = program.getSymbolTable()
        for symbol in symbol_table.getExternalSymbols():
            result['imports'].append({{
                'library': str(symbol.getParentNamespace()),
                'function': symbol.getName(),
                'address': str(symbol.getAddress())
            }})

        # Get exports
        for symbol in symbol_table.getExternalEntryPointIterator():
            result['exports'].append({{
                'name': str(symbol),
                'address': str(symbol)
            }})

        decompiler.dispose()

    except Exception as e:
        result['error'] = str(e)

    # Write output
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(result, f)

main()
'''


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        app,
        host='0.0.0.0',
        port=9270,
        workers=2,
        log_level='info'
    )
