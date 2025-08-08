from flask import Blueprint, jsonify, current_app
from app import db
from core.redis_client import redis_client
from mineral.storage.local_fs import LocalFileSystemStorage
from mineral.blockchain.polygon_logger import PolygonBlockchainLogger
from mineral.blockchain.base import MockBlockchainLogger
from mineral.encryption.key_manager import key_manager
from core.config import settings
import time
import os

health_bp = Blueprint('health', __name__)

@health_bp.route('/live', methods=['GET'])
def liveness():
    """Liveness probe - basic application health"""
    try:
        return jsonify({
            "status": "healthy",
            "timestamp": int(time.time()),
            "version": "1.0.0",
            "service": "qss4-backend"
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Liveness check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": int(time.time())
        }), 503

@health_bp.route('/ready', methods=['GET'])
def readiness():
    """Readiness probe - check all dependencies"""
    checks = {}
    overall_healthy = True
    
    try:
        # Database check
        try:
            db.session.execute(db.text('SELECT 1'))
            checks["database"] = {"status": "healthy", "message": "Connection successful"}
        except Exception as e:
            checks["database"] = {"status": "unhealthy", "error": str(e)}
            overall_healthy = False
        
        # Redis check
        try:
            if redis_client.ping():
                checks["redis"] = {"status": "healthy", "message": "Connection successful"}
            else:
                checks["redis"] = {"status": "unhealthy", "error": "Ping failed"}
                overall_healthy = False
        except Exception as e:
            checks["redis"] = {"status": "unhealthy", "error": str(e)}
            overall_healthy = False
        
        # Storage check
        try:
            storage_config = {"storage_path": settings.storage_path}
            storage = LocalFileSystemStorage(storage_config)
            
            # Check if storage directory exists and is writable
            storage_path = storage.storage_root
            if storage_path.exists() and os.access(storage_path, os.W_OK):
                storage_info = storage.get_storage_info()
                checks["storage"] = {
                    "status": "healthy", 
                    "message": "Storage accessible",
                    "info": storage_info
                }
            else:
                checks["storage"] = {
                    "status": "unhealthy", 
                    "error": "Storage directory not accessible"
                }
                overall_healthy = False
        except Exception as e:
            checks["storage"] = {"status": "unhealthy", "error": str(e)}
            overall_healthy = False
        
        # Encryption keys check
        try:
            if key_manager.keypair_exists():
                # Try to load keys
                public_key = key_manager.get_public_key()
                checks["encryption"] = {
                    "status": "healthy",
                    "message": "Kyber keypair available",
                    "public_key_size": len(public_key)
                }
            else:
                checks["encryption"] = {
                    "status": "warning",
                    "message": "Kyber keypair not found - will use mock implementation"
                }
                # Don't mark as unhealthy, just warning
        except Exception as e:
            checks["encryption"] = {"status": "unhealthy", "error": str(e)}
            overall_healthy = False
        
        # Blockchain check (optional)
        try:
            # Initialize blockchain logger based on configuration
            if settings.polygon_private_key:
                blockchain_config = {
                    "rpc_url": settings.polygon_rpc_url,
                    "private_key": settings.polygon_private_key,
                    "contract_address": settings.audit_contract_address
                }
                blockchain_logger = PolygonBlockchainLogger(blockchain_config)
            else:
                blockchain_logger = MockBlockchainLogger()
            
            if blockchain_logger.is_enabled():
                network_status = blockchain_logger.get_network_status()
                if network_status.get("status") == "connected":
                    checks["blockchain"] = {
                        "status": "healthy",
                        "message": f"{network_status['network']} network connected",
                        "network_info": network_status
                    }
                else:
                    checks["blockchain"] = {
                        "status": "warning",
                        "message": f"Blockchain connection issue: {network_status.get('error', 'Unknown')}",
                        "network_info": network_status
                    }
            else:
                checks["blockchain"] = {
                    "status": "disabled",
                    "message": "Blockchain logging disabled or mock mode"
                }
        except Exception as e:
            checks["blockchain"] = {"status": "warning", "error": str(e)}
            # Don't mark as unhealthy since blockchain is optional
        
        # Overall status
        status = "healthy" if overall_healthy else "unhealthy"
        status_code = 200 if overall_healthy else 503
        
        return jsonify({
            "status": status,
            "timestamp": int(time.time()),
            "checks": checks,
            "service": "qss4-backend",
            "version": "1.0.0"
        }), status_code
    
    except Exception as e:
        current_app.logger.error(f"Readiness check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": f"Health check failed: {str(e)}",
            "timestamp": int(time.time()),
            "checks": checks
        }), 503

@health_bp.route('/detailed', methods=['GET'])
def detailed_health():
    """Detailed health information with system metrics"""
    try:
        # Get basic readiness info
        readiness_response = readiness()
        readiness_data = readiness_response[0].get_json()
        
        # Add system information
        import psutil
        import platform
        
        system_info = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "total": psutil.disk_usage('/').total,
                "free": psutil.disk_usage('/').free,
                "percent": psutil.disk_usage('/').percent
            }
        }
        
        # Add configuration info (without sensitive data)
        config_info = {
            "storage_backend": settings.storage_backend,
            "compression_level": settings.compression_level,
            "rate_limit_enabled": settings.rate_limit_enabled,
            "max_file_size": settings.max_file_size
        }
        
        readiness_data["system_info"] = system_info
        readiness_data["configuration"] = config_info
        
        return jsonify(readiness_data), readiness_response[1]
    
    except Exception as e:
        current_app.logger.error(f"Detailed health check failed: {e}")
        return jsonify({
            "status": "error",
            "error": f"Detailed health check failed: {str(e)}",
            "timestamp": int(time.time())
        }), 500

@health_bp.route('/metrics', methods=['GET'])
def metrics():
    """Application metrics in Prometheus format"""
    try:
        from models import User, FileRecord, AuditLog
        
        # Basic metrics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        total_files = FileRecord.query.filter_by(deleted=False).count()
        total_audit_logs = AuditLog.query.count()
        
        # Storage metrics
        total_storage_bytes = db.session.query(
            db.func.sum(FileRecord.size)
        ).filter(FileRecord.deleted == False).scalar() or 0
        
        # Format as Prometheus metrics
        metrics_text = f"""# HELP qss4_users_total Total number of users
# TYPE qss4_users_total gauge
qss4_users_total {total_users}

# HELP qss4_users_active Active users
# TYPE qss4_users_active gauge
qss4_users_active {active_users}

# HELP qss4_files_total Total number of files
# TYPE qss4_files_total gauge
qss4_files_total {total_files}

# HELP qss4_storage_bytes_total Total storage used in bytes
# TYPE qss4_storage_bytes_total gauge
qss4_storage_bytes_total {total_storage_bytes}

# HELP qss4_audit_logs_total Total audit log entries
# TYPE qss4_audit_logs_total gauge
qss4_audit_logs_total {total_audit_logs}

# HELP qss4_health_status Health status (1 = healthy, 0 = unhealthy)
# TYPE qss4_health_status gauge
qss4_health_status 1
"""
        
        from flask import Response
        return Response(metrics_text, mimetype='text/plain')
    
    except Exception as e:
        current_app.logger.error(f"Metrics endpoint failed: {e}")
        error_metrics = f"""# HELP qss4_health_status Health status (1 = healthy, 0 = unhealthy)
# TYPE qss4_health_status gauge
qss4_health_status 0
"""
        from flask import Response
        return Response(error_metrics, mimetype='text/plain'), 500
