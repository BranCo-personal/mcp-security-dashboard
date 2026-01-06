"""
MCP Security Dashboard - FastAPI Backend
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uuid

from .models import ScanRequest, ScanResponse, ScanResult, VulnerabilityDetail
from .scanner import MCPScanner
from .database import Database

app = FastAPI(
    title="MCP Security Dashboard",
    description="Scan MCP servers for security vulnerabilities",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
db = Database()
scanner = MCPScanner()


@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    db.init_db()


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "healthy", "service": "MCP Security Dashboard"}


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new MCP server security scan.
    
    The scan runs in the background and results can be fetched via GET /api/scan/{scan_id}
    """
    scan_id = str(uuid.uuid4())
    
    # Create initial scan record
    db.create_scan(
        scan_id=scan_id,
        target=request.target,
        scan_type=request.scan_type,
        status="running"
    )
    
    # Run scan in background
    background_tasks.add_task(run_scan_task, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message=f"Scan started for {request.target}"
    )


async def run_scan_task(scan_id: str, request: ScanRequest):
    """Background task to run the actual scan."""
    try:
        # Run the scanner
        results = await scanner.scan(
            target=request.target,
            scan_type=request.scan_type,
            options=request.options
        )
        
        # Store results
        db.update_scan(
            scan_id=scan_id,
            status="completed",
            results=results
        )
        
    except Exception as e:
        db.update_scan(
            scan_id=scan_id,
            status="failed",
            error=str(e)
        )


@app.get("/api/scan/{scan_id}", response_model=ScanResult)
async def get_scan_results(scan_id: str):
    """Get results for a specific scan."""
    result = db.get_scan(scan_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return result


@app.get("/api/scans", response_model=list[ScanResult])
async def list_scans(limit: int = 20):
    """List recent scans."""
    return db.list_scans(limit=limit)


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its results."""
    success = db.delete_scan(scan_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {"status": "deleted", "scan_id": scan_id}


@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics."""
    return db.get_stats()


# Quick scan endpoint for demo purposes
@app.post("/api/quick-scan")
async def quick_scan(request: ScanRequest):
    """
    Run a quick synchronous scan (for demo/testing).
    Use /api/scan for production workloads.
    """
    try:
        results = await scanner.scan(
            target=request.target,
            scan_type=request.scan_type,
            options=request.options
        )
        
        return {
            "status": "completed",
            "target": request.target,
            "vulnerabilities": results,
            "summary": {
                "total": len(results),
                "critical": len([v for v in results if v.get("risk_level") == "CRITICAL"]),
                "high": len([v for v in results if v.get("risk_level") == "HIGH"]),
                "medium": len([v for v in results if v.get("risk_level") == "MEDIUM"]),
                "low": len([v for v in results if v.get("risk_level") == "LOW"]),
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
