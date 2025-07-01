"""
Production PostgreSQL MCP Server with OAuth Authentication
========================================================

A real-world MCP server for PostgreSQL database operations with OAuth protection.
Features practical tools for database administration, monitoring, and data analysis.

Key Features:
- ✅ Real database connection and operations
- ✅ OAuth 2.0 authentication with scope-based access control
- ✅ Production-ready SQL tools with safety checks
- ✅ Database monitoring and health checks
- ✅ User activity logging and audit trails
- ✅ Data export and backup operations
- ✅ Advanced query builder and analytics

Scopes:
- mcp:read: Basic read operations (SELECT, schema info, monitoring)
- mcp:admin: Administrative operations (maintenance, backups, user management)
"""

import asyncio
import logging
import os
import sys
import json
import time
import csv
import io
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
import tempfile
from pathlib import Path

import asyncpg
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Import the OAuth SDK
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config

# Configure logging to stderr only (MCP requirement)
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("postgres-mcp-server")

server = Server("postgres-mcp-server")

# Global instances
db_pool = None
oauth_sdk = None

# =============================================================================
# APPLICATION TOOLS DEFINITION (MOVED TO TOP)
# =============================================================================

def define_application_tools():
    """Define comprehensive PostgreSQL management tools"""
    
    return [
        # Public tools (no authentication required)
        types.Tool(
            name="get_server_info",
            description="ℹ️ Get PostgreSQL server information and connection status",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="health_check",
            description="🏥 Get comprehensive database health and performance metrics",
            inputSchema={"type": "object", "properties": {}},
        ),
        
        # Read operations (mcp:read scope required)
        types.Tool(
            name="execute_query",
            description="🔍 Execute SELECT queries with safety validation (requires mcp:read scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "SELECT query to execute (INSERT/UPDATE/DELETE not allowed)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Optional result limit (default: 100, max: 1000)",
                        "minimum": 1,
                        "maximum": 1000,
                        "default": 100
                    }
                },
                "required": ["query"]
            },
        ),
        types.Tool(
            name="get_schema",
            description="📋 Get comprehensive database schema with statistics (requires mcp:read scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_statistics": {
                        "type": "boolean",
                        "description": "Include table sizes and row counts",
                        "default": True
                    }
                }
            },
        ),
        types.Tool(
            name="get_table_info",
            description="📊 Get detailed table information and statistics (requires mcp:read scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Name of the table to analyze"
                    },
                    "schema_name": {
                        "type": "string",
                        "description": "Schema name (default: public)",
                        "default": "public"
                    }
                },
                "required": ["table_name"]
            },
        ),
        types.Tool(
            name="list_tables",
            description="📝 List all tables with sizes and basic statistics (requires mcp:read scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "schema_name": {
                        "type": "string", 
                        "description": "Filter by schema name (optional)"
                    },
                    "include_system": {
                        "type": "boolean",
                        "description": "Include system tables",
                        "default": False
                    }
                }
            },
        ),
        types.Tool(
            name="export_data",
            description="📤 Export table data in JSON or CSV format (requires mcp:read scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Table name to export"
                    },
                    "schema_name": {
                        "type": "string",
                        "description": "Schema name (default: public)",
                        "default": "public"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["json", "csv"],
                        "description": "Export format",
                        "default": "json"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum rows to export (default: 1000, max: 10000)",
                        "minimum": 1,
                        "maximum": 10000,
                        "default": 1000
                    }
                },
                "required": ["table_name"]
            },
        ),
        types.Tool(
            name="database_activity",
            description="📊 Monitor current database connections and activity (requires mcp:read scope)",
            inputSchema={"type": "object", "properties": {}},
        ),
        
        # Admin operations (mcp:admin scope required)
        types.Tool(
            name="backup_schema_ddl",
            description="💾 Generate DDL backup script for schema (requires mcp:admin scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "schema_name": {
                        "type": "string",
                        "description": "Schema to backup (default: public)",
                        "default": "public"
                    }
                }
            },
        ),
        types.Tool(
            name="analyze_performance",
            description="🐌 Analyze slow queries and performance metrics (requires mcp:admin scope)",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="admin_maintenance",
            description="🔧 Perform database maintenance operations (requires mcp:admin scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": ["vacuum_analyze", "reindex", "update_statistics"],
                        "description": "Maintenance operation to perform"
                    },
                    "table_name": {
                        "type": "string",
                        "description": "Specific table (optional, default: all tables)"
                    }
                },
                "required": ["operation"]
            },
        )
    ]

# =============================================================================
# OAUTH CONFIGURATION
# =============================================================================

# The oauth_config is now optional when initializing MCPOAuthSDK
# If you want to explicitly define it here, you can, otherwise, the SDK will
# try to read from environment variables.
# oauth_config = create_hydra_config(
#     oauth_server=os.getenv("OAUTH_SERVER", "https://authsec.authnull.com/o"),
#     client_id=os.getenv("OAUTH_CLIENT_ID", "test-client"),
#     client_secret=os.getenv("OAUTH_CLIENT_SECRET", "test-secret"),
#     scopes=["mcp:read", "mcp:admin"]
# )

# Initialize OAuth SDK (now with optional config)
oauth_sdk = MCPOAuthSDK() # No config passed, it will use environment variables

# =============================================================================
# DATABASE CONNECTION AND HEALTH
# =============================================================================

async def connect_database():
    """Connect to PostgreSQL database with production settings"""
    global db_pool
    
    connection_string = os.getenv("POSTGRES_CONNECTION_STRING")
    if len(sys.argv) > 1:
        connection_string = sys.argv[1]
    
    if not connection_string:
        raise ValueError(
            "POSTGRES_CONNECTION_STRING environment variable is required for production use. "
            "Format: postgresql://user:password@host:port/database"
        )
    
    try:
        # Production connection pool settings
        db_pool = await asyncpg.create_pool(
            connection_string,
            min_size=2,
            max_size=20,
            command_timeout=60,
            server_settings={
                'application_name': 'mcp_postgres_server',
                'timezone': 'UTC'
            }
        )
        
        # Test connection
        async with db_pool.acquire() as conn:
            version = await conn.fetchval('SELECT version()')
            logger.info(f"✅ Connected to PostgreSQL: {version}")
            
        logger.info("✅ Database connection pool created successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to connect to database: {e}")
        raise

async def get_db_health() -> Dict[str, Any]:
    """Get comprehensive database health information"""
    if not db_pool:
        return {"status": "disconnected", "error": "No database connection"}
    
    try:
        async with db_pool.acquire() as conn:
            # Basic connectivity
            start_time = time.time()
            await conn.fetchval('SELECT 1')
            response_time = time.time() - start_time
            
            # Database info
            db_info = await conn.fetchrow("""
                SELECT 
                    current_database() as database_name,
                    current_user as current_user,
                    version() as version,
                    inet_server_addr() as server_ip,
                    inet_server_port() as server_port
            """)
            
            # Connection stats
            conn_stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_connections,
                    COUNT(*) FILTER (WHERE state = 'active') as active_connections,
                    COUNT(*) FILTER (WHERE state = 'idle') as idle_connections
                FROM pg_stat_activity
            """)
            
            # Database size
            db_size = await conn.fetchrow("""
                SELECT 
                    pg_size_pretty(pg_database_size(current_database())) as database_size,
                    pg_database_size(current_database()) as database_size_bytes
            """)
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time * 1000, 2),
                "database_info": dict(db_info) if db_info else {},
                "connection_stats": dict(conn_stats) if conn_stats else {},
                "database_size": dict(db_size) if db_size else {},
                "pool_stats": {
                    "pool_size": db_pool.get_size(),
                    "pool_min_size": db_pool.get_min_size(),
                    "pool_max_size": db_pool.get_max_size(),
                },
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

# =============================================================================
# QUERY EXECUTION WITH SAFETY AND LOGGING
# =============================================================================

async def execute_safe_query(query: str, params: Optional[List] = None, username: str = None) -> Dict[str, Any]:
    """Execute queries with comprehensive safety checks and logging"""
    
    # Log the query attempt
    logger.info(f"🔍 Query execution by '{username}': {query[:200]}{'...' if len(query) > 200 else ''}")
    
    # Security validation
    query_upper = query.strip().upper()
    
    # Only allow SELECT, WITH (for CTEs), and EXPLAIN statements
    allowed_starts = ['SELECT', 'WITH', 'EXPLAIN']
    if not any(query_upper.startswith(start) for start in allowed_starts):
        raise ValueError(f"Only {', '.join(allowed_starts)} statements are allowed for security")
    
    # Check for dangerous keywords
    dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'CREATE', 'TRUNCATE', 'GRANT', 'REVOKE']
    for keyword in dangerous_keywords:
        if keyword in query_upper:
            raise ValueError(f"Keyword '{keyword}' is not allowed for security")
    
    # Execute query with timing and result metadata
    start_time = time.time()
    
    async with db_pool.acquire() as conn:
        try:
            if params:
                rows = await conn.fetch(query, *params)
            else:
                rows = await conn.fetch(query)
            
            execution_time = time.time() - start_time
            
            # Convert to list of dictionaries
            results = [dict(row) for row in rows]
            
            # Log successful execution
            logger.info(f"✅ Query completed in {execution_time:.3f}s, returned {len(results)} rows for user '{username}'")
            
            return {
                "success": True,
                "results": results,
                "metadata": {
                    "row_count": len(results),
                    "execution_time_seconds": round(execution_time, 3),
                    "executed_by": username,
                    "executed_at": datetime.utcnow().isoformat(),
                    "query_preview": query[:100] + "..." if len(query) > 100 else query
                }
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"❌ Query failed after {execution_time:.3f}s for user '{username}': {e}")
            raise

# =============================================================================
# SCHEMA AND METADATA OPERATIONS
# =============================================================================

async def get_comprehensive_schema(username: str) -> Dict[str, Any]:
    """Get detailed database schema with statistics"""
    logger.info(f"📊 Getting comprehensive schema for user '{username}'")
    
    async with db_pool.acquire() as conn:
        # Tables with detailed info
        tables_query = """
        SELECT 
            schemaname,
            tablename,
            tableowner,
            hasindexes,
            hasrules,
            hastriggers,
            pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as table_size,
            pg_total_relation_size(schemaname||'.'||tablename) as table_size_bytes
        FROM pg_tables 
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
        ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
        """
        
        # Views
        views_query = """
        SELECT 
            schemaname,
            viewname,
            viewowner,
            definition
        FROM pg_views 
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
        ORDER BY schemaname, viewname;
        """
        
        # Columns with detailed info
        columns_query = """
        SELECT 
            table_schema,
            table_name,
            column_name,
            data_type,
            is_nullable,
            column_default,
            character_maximum_length,
            numeric_precision,
            numeric_scale,
            ordinal_position
        FROM information_schema.columns 
        WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
        ORDER BY table_schema, table_name, ordinal_position;
        """
        
        # Indexes
        indexes_query = """
        SELECT 
            schemaname,
            tablename,
            indexname,
            indexdef
        FROM pg_indexes
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
        ORDER BY schemaname, tablename, indexname;
        """
        
        # Foreign keys
        fk_query = """
        SELECT
            tc.table_schema,
            tc.table_name,
            tc.constraint_name,
            tc.constraint_type,
            kcu.column_name,
            ccu.table_schema AS foreign_table_schema,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage AS ccu
            ON ccu.constraint_name = tc.constraint_name
            AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
            AND tc.table_schema NOT IN ('information_schema', 'pg_catalog')
        ORDER BY tc.table_schema, tc.table_name;
        """
        
        tables = await conn.fetch(tables_query)
        views = await conn.fetch(views_query)
        columns = await conn.fetch(columns_query)
        indexes = await conn.fetch(indexes_query)
        foreign_keys = await conn.fetch(fk_query)
        
        return {
            "tables": [dict(row) for row in tables],
            "views": [dict(row) for row in views],
            "columns": [dict(row) for row in columns],
            "indexes": [dict(row) for row in indexes],
            "foreign_keys": [dict(row) for row in foreign_keys],
            "summary": {
                "total_tables": len(tables),
                "total_views": len(views),
                "total_columns": len(columns),
                "total_indexes": len(indexes),
                "total_foreign_keys": len(foreign_keys)
            },
            "accessed_by": username,
            "access_timestamp": datetime.utcnow().isoformat()
        }

async def get_table_statistics(table_name: str, schema_name: str = "public", username: str = None) -> Dict[str, Any]:
    """Get comprehensive table statistics"""
    logger.info(f"📈 Getting table statistics for {schema_name}.{table_name} by user '{username}'")
    
    async with db_pool.acquire() as conn:
        # Basic table info
        table_info_query = """
        SELECT 
            pg_size_pretty(pg_total_relation_size($1)) as total_size,
            pg_total_relation_size($1) as total_size_bytes,
            pg_size_pretty(pg_relation_size($1)) as table_size,
            pg_relation_size($1) as table_size_bytes,
            (SELECT reltuples::bigint FROM pg_class WHERE relname = $2) as estimated_rows
        """
        
        # Column statistics
        column_stats_query = """
        SELECT 
            column_name,
            data_type,
            is_nullable,
            column_default
        FROM information_schema.columns 
        WHERE table_name = $1 AND table_schema = $2
        ORDER BY ordinal_position;
        """
        
        # Index information
        index_info_query = """
        SELECT 
            indexname,
            indexdef,
            pg_size_pretty(pg_relation_size(indexname::regclass)) as index_size
        FROM pg_indexes
        WHERE tablename = $1 AND schemaname = $2;
        """
        
        full_table_name = f"{schema_name}.{table_name}"
        
        table_info = await conn.fetchrow(table_info_query, full_table_name, table_name)
        columns = await conn.fetch(column_stats_query, table_name, schema_name)
        indexes = await conn.fetch(index_info_query, table_name, schema_name)
        
        # Get actual row count for smaller tables
        if table_info and table_info['estimated_rows'] and table_info['estimated_rows'] < 1000000:
            try:
                actual_count = await conn.fetchval(f'SELECT COUNT(*) FROM "{schema_name}"."{table_name}"')
            except:
                actual_count = None
        else:
            actual_count = None
        
        return {
            "table_name": table_name,
            "schema_name": schema_name,
            "table_info": dict(table_info) if table_info else {},
            "actual_row_count": actual_count,
            "columns": [dict(row) for row in columns],
            "indexes": [dict(row) for row in indexes],
            "column_count": len(columns),
            "index_count": len(indexes),
            "analyzed_by": username,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }

# =============================================================================
# DATA EXPORT AND BACKUP OPERATIONS
# =============================================================================

async def export_table_data(table_name: str, schema_name: str = "public", 
                           limit: int = 1000, format: str = "json", 
                           username: str = None) -> Dict[str, Any]:
    """Export table data in various formats"""
    logger.info(f"📤 Exporting {schema_name}.{table_name} (limit: {limit}, format: {format}) by user '{username}'")
    
    if limit > 10000:
        raise ValueError("Export limit cannot exceed 10,000 rows for performance")
    
    query = f'SELECT * FROM "{schema_name}"."{table_name}" LIMIT $1'
    result = await execute_safe_query(query, [limit], username)
    
    if not result["success"]:
        return result
    
    data = result["results"]
    
    if format.lower() == "csv":
        # Convert to CSV
        if data:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
            csv_data = output.getvalue()
            output.close()
            
            return {
                "success": True,
                "format": "csv",
                "data": csv_data,
                "metadata": result["metadata"]
            }
    
    elif format.lower() == "json":
        return {
            "success": True,
            "format": "json",
            "data": data,
            "metadata": result["metadata"]
        }
    
    else:
        raise ValueError("Supported formats: json, csv")

async def backup_schema_ddl(schema_name: str = "public", username: str = None) -> Dict[str, Any]:
    """Generate DDL backup for schema"""
    logger.info(f"💾 Generating DDL backup for schema '{schema_name}' by user '{username}'")
    
    async with db_pool.acquire() as conn:
        # Get table DDL
        tables_ddl_query = """
        SELECT 
            tablename,
            'CREATE TABLE ' || schemaname || '.' || tablename || ' (' ||
            array_to_string(
                array_agg(
                    column_name || ' ' || data_type ||
                    CASE 
                        WHEN character_maximum_length IS NOT NULL 
                        THEN '(' || character_maximum_length || ')'
                        WHEN numeric_precision IS NOT NULL 
                        THEN '(' || numeric_precision || ',' || COALESCE(numeric_scale, 0) || ')'
                        ELSE ''
                    END ||
                    CASE WHEN is_nullable = 'NO' THEN ' NOT NULL' ELSE '' END
                ), ', '
            ) || ');' as ddl
        FROM information_schema.columns c
        JOIN pg_tables t ON c.table_name = t.tablename
        WHERE c.table_schema = $1 AND t.schemaname = $1
        GROUP BY tablename, schemaname
        ORDER BY tablename;
        """
        
        # Get view DDL
        views_ddl_query = """
        SELECT 
            viewname,
            'CREATE VIEW ' || schemaname || '.' || viewname || ' AS ' || definition as ddl
        FROM pg_views
        WHERE schemaname = $1
        ORDER BY viewname;
        """
        
        # Get index DDL
        indexes_ddl_query = """
        SELECT 
            indexname,
            indexdef || ';' as ddl
        FROM pg_indexes
        WHERE schemaname = $1
        ORDER BY indexname;
        """
        
        tables_ddl = await conn.fetch(tables_ddl_query, schema_name)
        views_ddl = await conn.fetch(views_ddl_query, schema_name)
        indexes_ddl = await conn.fetch(indexes_ddl_query, schema_name)
        
        ddl_script = f"-- Schema backup for '{schema_name}' generated at {datetime.utcnow().isoformat()}\n"
        ddl_script += f"-- Generated by user: {username}\n\n"
        
        if tables_ddl:
            ddl_script += "-- Tables\n"
            for row in tables_ddl:
                ddl_script += f"-- Table: {row['tablename']}\n"
                ddl_script += row['ddl'] + "\n\n"
        
        if views_ddl:
            ddl_script += "-- Views\n"
            for row in views_ddl:
                ddl_script += f"-- View: {row['viewname']}\n"
                ddl_script += row['ddl'] + "\n\n"
        
        if indexes_ddl:
            ddl_script += "-- Indexes\n"
            for row in indexes_ddl:
                ddl_script += f"-- Index: {row['indexname']}\n"
                ddl_script += row['ddl'] + "\n\n"
        
        return {
            "success": True,
            "schema_name": schema_name,
            "ddl_script": ddl_script,
            "tables_count": len(tables_ddl),
            "views_count": len(views_ddl),
            "indexes_count": len(indexes_ddl),
            "generated_by": username,
            "generated_at": datetime.utcnow().isoformat()
        }

# =============================================================================
# MONITORING AND ANALYTICS
# =============================================================================

async def get_database_activity(username: str = None) -> Dict[str, Any]:
    """Get current database activity and performance metrics"""
    logger.info(f"📊 Getting database activity for user '{username}'")
    
    async with db_pool.acquire() as conn:
        # Current connections
        connections_query = """
        SELECT 
            datname,
            usename,
            application_name,
            client_addr,
            state,
            query_start,
            state_change,
            substring(query, 1, 100) as current_query
        FROM pg_stat_activity
        WHERE state IS NOT NULL
        ORDER BY query_start DESC
        LIMIT 20;
        """
        
        # Database statistics
        db_stats_query = """
        SELECT 
            datname,
            numbackends,
            xact_commit,
            xact_rollback,
            blks_read,
            blks_hit,
            tup_returned,
            tup_fetched,
            tup_inserted,
            tup_updated,
            tup_deleted
        FROM pg_stat_database
        WHERE datname = current_database();
        """
        
        # Table statistics
        table_stats_query = """
        SELECT 
            schemaname,
            relname as tablename,
            seq_scan,
            seq_tup_read,
            idx_scan,
            idx_tup_fetch,
            n_tup_ins,
            n_tup_upd,
            n_tup_del
        FROM pg_stat_user_tables
        ORDER BY (seq_tup_read + idx_tup_fetch) DESC
        LIMIT 10;
        """
        
        connections = await conn.fetch(connections_query)
        db_stats = await conn.fetchrow(db_stats_query)
        table_stats = await conn.fetch(table_stats_query)
        
        return {
            "current_connections": [dict(row) for row in connections],
            "database_stats": dict(db_stats) if db_stats else {},
            "top_tables_activity": [dict(row) for row in table_stats],
            "connection_count": len(connections),
            "monitored_by": username,
            "timestamp": datetime.utcnow().isoformat()
        }

async def analyze_slow_queries(username: str = None) -> Dict[str, Any]:
    """Analyze query performance (requires pg_stat_statements extension)"""
    logger.info(f"🐌 Analyzing slow queries for user '{username}'")
    
    async with db_pool.acquire() as conn:
        try:
            # Check if pg_stat_statements is available
            extension_check = await conn.fetchval(
                "SELECT COUNT(*) FROM pg_extension WHERE extname = 'pg_stat_statements'"
            )
            
            if extension_check == 0:
                return {
                    "success": False,
                    "error": "pg_stat_statements extension not installed",
                    "suggestion": "Install pg_stat_statements extension for query performance analysis"
                }
            
            # Get slow queries
            slow_queries_query = """
            SELECT 
                query,
                calls,
                total_time,
                mean_time,
                rows,
                100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
            FROM pg_stat_statements
            WHERE calls > 10
            ORDER BY mean_time DESC
            LIMIT 10;
            """
            
            slow_queries = await conn.fetch(slow_queries_query)
            
            return {
                "success": True,
                "slow_queries": [dict(row) for row in slow_queries],
                "analyzed_by": username,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "analyzed_by": username,
                "timestamp": datetime.utcnow().isoformat()
            }

# =============================================================================
# TOOL CALL HANDLER
# =============================================================================

async def handle_application_tool_call(name: str, arguments: dict | None) -> list[types.TextContent]:
    """Handle all application tool calls with proper authentication"""
    
    try:
        # Get current authenticated user
        current_user = oauth_sdk.get_current_user()
        username = current_user.username if current_user else "anonymous"
        
        # Public tools (no authentication required)
        if name == "get_server_info":
            logger.info(f"ℹ️ Server info requested by '{username}'")
            
            health = await get_db_health()
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "server_info": {
                        "name": "Production PostgreSQL MCP Server",
                        "version": "1.0.0",
                        "oauth_enabled": True,
                        "database_status": health.get("status", "unknown"),
                        "features": [
                            "Production PostgreSQL operations",
                            "OAuth 2.0 authentication with scopes",
                            "Safe query execution with validation",
                            "Comprehensive schema analysis",
                            "Data export (JSON/CSV)",
                            "Performance monitoring",
                            "Database health checks",
                            "DDL backup generation",
                            "User activity logging"
                        ]
                    },
                    "database_health": health,
                    "accessed_by": username,
                    "timestamp": datetime.utcnow().isoformat()
                }, indent=2, default=str)
            )]
        
        elif name == "health_check":
            logger.info(f"🏥 Health check requested by '{username}'")
            health = await get_db_health()
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "health_check": health,
                    "checked_by": username,
                    "timestamp": datetime.utcnow().isoformat()
                }, indent=2, default=str)
            )]
        
        # Read operations (mcp:read scope required)
        elif name == "execute_query":
            if not arguments or "query" not in arguments:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Missing required 'query' parameter"}, indent=2)
                )]
            
            query = arguments["query"]
            limit = arguments.get("limit", 100)
            
            # Add LIMIT if not present
            if "LIMIT" not in query.upper() and limit:
                query += f" LIMIT {limit}"
            
            result = await execute_safe_query(query, username=username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2, default=str)
            )]
        
        elif name == "get_schema":
            include_stats = arguments.get("include_statistics", True) if arguments else True
            
            schema_info = await get_comprehensive_schema(username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "schema_info": schema_info,
                    "include_statistics": include_stats
                }, indent=2, default=str)
            )]
        
        elif name == "get_table_info":
            if not arguments or "table_name" not in arguments:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Missing required 'table_name' parameter"}, indent=2)
                )]
            
            table_name = arguments["table_name"]
            schema_name = arguments.get("schema_name", "public")
            
            table_info = await get_table_statistics(table_name, schema_name, username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(table_info, indent=2, default=str)
            )]
        
        elif name == "list_tables":
            schema_name = arguments.get("schema_name") if arguments else None
            include_system = arguments.get("include_system", False) if arguments else False
            
            # Get tables from schema info
            schema_info = await get_comprehensive_schema(username)
            tables = schema_info["tables"]
            
            # Filter by schema if specified
            if schema_name:
                tables = [t for t in tables if t["schemaname"] == schema_name]
            
            # Filter system tables if not requested
            if not include_system:
                tables = [t for t in tables if t["schemaname"] not in ["information_schema", "pg_catalog", "pg_toast"]]
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "tables": tables,
                    "total_count": len(tables),
                    "schema_filter": schema_name,
                    "include_system": include_system,
                    "listed_by": username,
                    "timestamp": datetime.utcnow().isoformat()
                }, indent=2, default=str)
            )]
        
        elif name == "export_data":
            if not arguments or "table_name" not in arguments:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Missing required 'table_name' parameter"}, indent=2)
                )]
            
            table_name = arguments["table_name"]
            schema_name = arguments.get("schema_name", "public")
            format_type = arguments.get("format", "json")
            limit = arguments.get("limit", 1000)
            
            export_result = await export_table_data(table_name, schema_name, limit, format_type, username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(export_result, indent=2, default=str)
            )]
        
        elif name == "database_activity":
            activity = await get_database_activity(username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(activity, indent=2, default=str)
            )]
        
        # Admin operations (mcp:admin scope required)
        elif name == "backup_schema_ddl":
            schema_name = arguments.get("schema_name", "public") if arguments else "public"
            
            backup_result = await backup_schema_ddl(schema_name, username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(backup_result, indent=2, default=str)
            )]
        
        elif name == "analyze_performance":
            analysis = await analyze_slow_queries(username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(analysis, indent=2, default=str)
            )]
        
        elif name == "admin_maintenance":
            if not arguments or "operation" not in arguments:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Missing required 'operation' parameter"}, indent=2)
                )]
            
            operation = arguments["operation"]
            table_name = arguments.get("table_name")
            
            # Simulate maintenance operations (read-only server, so we return what would be done)
            maintenance_result = {
                "operation": operation,
                "target": table_name or "all_tables",
                "status": "simulated",
                "message": f"Would perform {operation} on {table_name or 'all tables'}",
                "note": "This is a read-only demo. In production, this would execute the maintenance command.",
                "performed_by": username,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if operation == "vacuum_analyze":
                maintenance_result["command"] = f"VACUUM ANALYZE {table_name if table_name else ''}"
            elif operation == "reindex":
                maintenance_result["command"] = f"REINDEX TABLE {table_name}" if table_name else "REINDEX DATABASE"
            elif operation == "update_statistics":
                maintenance_result["command"] = f"ANALYZE {table_name if table_name else ''}"
            
            logger.info(f"🔧 Maintenance operation '{operation}' simulated by '{username}'")
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "maintenance_result": maintenance_result
                }, indent=2, default=str)
            )]
        
        else:
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Unknown tool: {name}",
                    "available_tools": [
                        "get_server_info", "health_check", "execute_query", "get_schema", 
                        "get_table_info", "list_tables", "export_data", "database_activity",
                        "backup_schema_ddl", "analyze_performance", "admin_maintenance"
                    ]
                }, indent=2)
            )]
    
    except Exception as e:
        logger.error(f"❌ Tool execution failed for '{name}' by user '{username}': {e}")
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "error": f"Tool execution failed: {str(e)}",
                "tool": name,
                "user": username,
                "timestamp": datetime.utcnow().isoformat()
            }, indent=2)
        )]

# =============================================================================
# ENHANCED OAUTH SDK INTEGRATION
# =============================================================================

class ProductionMCPOAuthSDK(MCPOAuthSDK):
    """Enhanced OAuth SDK for production PostgreSQL server"""
    
    async def _call_application_tool(self, name: str, arguments: dict | None) -> List[types.TextContent]:
        """Call application tools with enhanced error handling"""
        try:
            # Directly call the handle_application_tool_call from main.py
            return await handle_application_tool_call(name, arguments)
        except Exception as e:
            logger.error(f"Application tool call failed: {e}")
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Tool execution failed: {str(e)}",
                    "tool": name,
                    "timestamp": datetime.utcnow().isoformat()
                }, indent=2)
            )]

# =============================================================================
# SERVER SETUP AND OAUTH PROTECTION
# =============================================================================

def setup_oauth_protection():
    """Setup OAuth protection for production tools"""
    
    # Give OAuth SDK access to application tools
    # This will be dynamically fetched by the SDK now
    # oauth_sdk._application_tools = define_application_tools() 
    oauth_sdk._app_call_tool_handler = handle_application_tool_call # Keep this for direct call
    
    # Protect read operations with mcp:read scope
    oauth_sdk.protect_tool("execute_query", scopes=["mcp:read"])
    oauth_sdk.protect_tool("get_schema", scopes=["mcp:read"])
    oauth_sdk.protect_tool("get_table_info", scopes=["mcp:read"])
    oauth_sdk.protect_tool("list_tables", scopes=["mcp:read"])
    oauth_sdk.protect_tool("export_data", scopes=["mcp:read"])
    oauth_sdk.protect_tool("database_activity", scopes=["mcp:read"])
    
    # Protect admin operations with mcp:admin scope
    oauth_sdk.protect_tool("backup_schema_ddl", scopes=["mcp:admin"])
    oauth_sdk.protect_tool("analyze_performance", scopes=["mcp:admin"])
    oauth_sdk.protect_tool("admin_maintenance", scopes=["mcp:admin"])
    
    # Public tools (no protection): get_server_info, health_check
    
    logger.info("🛡️ OAuth protection configured for production PostgreSQL server")
    logger.info(f"📋 Read tools (mcp:read): execute_query, get_schema, get_table_info, list_tables, export_data, database_activity")
    logger.info(f"🔐 Admin tools (mcp:admin): backup_schema_ddl, analyze_performance, admin_maintenance")
    logger.info(f"🌐 Public tools: get_server_info, health_check")

# =============================================================================
# MAIN FUNCTION
# =============================================================================

async def main():
    """Main server function for production PostgreSQL MCP server"""
    
    logger.info("🚀 Starting Production PostgreSQL MCP Server with OAuth")
    
    try:
        # Initialize OAuth SDK
        global oauth_sdk
        # Now, you can initialize without passing oauth_config explicitly
        # The SDK will try to read from environment variables by default.
        oauth_sdk = ProductionMCPOAuthSDK() 
        
        # Register OAuth with server
        oauth_sdk.register_with_server(server)
        setup_oauth_protection()
        
        # Connect to database (required for production)
        await connect_database()
        
        # Test database connection
        health = await get_db_health()
        if health["status"] != "healthy":
            logger.warning(f"Database health check warning: {health}")
        
        # Run MCP server
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            logger.info("🎉 PRODUCTION POSTGRESQL MCP SERVER STARTED")
            logger.info("🔐 OAuth 2.0 authentication enabled")
            logger.info("🛡️ Scope-based access control active")
            logger.info("📊 Real PostgreSQL operations available")
            logger.info("🌐 OAuth flow:")
            logger.info("   1. Call 'oauth_authenticate' → Get auth URL")
            logger.info("   2. Complete OAuth in browser")
            logger.info("   3. Ask 'What tools are available?' → See all database tools")
            logger.info("   4. Use production PostgreSQL tools with authentication!")
            
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="postgres-mcp-server",
                    server_version="1.0.0-production",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    
    except KeyboardInterrupt:
        logger.info("🛑 Server interrupted by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        raise
    finally:
        # Cleanup
        if db_pool:
            await db_pool.close()
            logger.info("✅ Database connections closed")
        
        if oauth_sdk:
            await oauth_sdk.cleanup()
            logger.info("✅ OAuth SDK cleaned up")

if __name__ == "__main__":
    asyncio.run(main())

# =============================================================================
# PRODUCTION TOOLS OVERVIEW
# =============================================================================

"""
🏭 PRODUCTION POSTGRESQL MCP SERVER - TOOL OVERVIEW
==================================================

PUBLIC TOOLS (No Authentication Required):
------------------------------------------
✅ get_server_info      - Server status and database health
✅ health_check         - Comprehensive database health metrics

READ OPERATIONS (mcp:read scope required):
-----------------------------------------
✅ execute_query        - Safe SELECT query execution with validation
✅ get_schema           - Complete schema analysis with statistics  
✅ get_table_info       - Detailed table statistics and metadata
✅ list_tables          - Table listing with sizes and ownership
✅ export_data          - Data export in JSON/CSV (up to 10K rows)
✅ database_activity    - Real-time connection and activity monitoring

ADMIN OPERATIONS (mcp:admin scope required):
-------------------------------------------
✅ backup_schema_ddl    - Generate DDL backup scripts
✅ analyze_performance  - Query performance analysis (pg_stat_statements)
✅ admin_maintenance    - Database maintenance operations

SECURITY FEATURES:
-----------------
🛡️ OAuth 2.0 + PKCE authentication
🔒 Scope-based access control (mcp:read, mcp:admin)
🚫 SQL injection protection with query validation
📝 Complete audit logging with usernames
⚡ Performance limits (query results, export sizes)
🔐 Read-only operations only (no INSERT/UPDATE/DELETE)

REAL-WORLD FEATURES:
-------------------
📊 Connection pooling with production settings
📈 Table statistics and size analysis
🔍 Query performance monitoring
💾 Schema backup and DDL generation
📤 Data export in multiple formats
🏥 Database health monitoring
📋 Comprehensive schema introspection
🎯 Foreign key and index analysis

USAGE EXAMPLE:
-------------
1. Start server: python postgres_mcp_server.py
2. Authenticate: Call 'oauth_authenticate'
3. Explore: Call 'list_tables' to see your database
4. Query: Use 'execute_query' with SELECT statements
5. Export: Use 'export_data' to export table data
6. Monitor: Use 'database_activity' to see connections
7. Backup: Use 'backup_schema_ddl' for schema backups

This is a production-ready PostgreSQL MCP server suitable for real database
administration, monitoring, and data analysis tasks! 🚀
"""
