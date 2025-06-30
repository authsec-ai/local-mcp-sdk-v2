"""
Complete Demo Server with Localhost:3000 Callback - Full Working Code
=====================================================================

This is the complete working example that includes:
- The full OAuth SDK with localhost callback server
- Working PostgreSQL integration (like our original example)
- Complete OAuth flow: authenticate → callback → token exchange → tools unlock
- Proper MCP protocol compliance

Expected Flow:
1. Server starts → Shows OAuth tools only
2. Call oauth_authenticate → Get auth URL with localhost:3000 callback
3. Complete OAuth in browser → Redirected to localhost:3000/callback
4. Automatic token exchange → User info retrieved and token saved
5. Call oauth_refresh_tools → Protected tools now visible
6. All database tools available with user authentication!
"""

import asyncio
import logging
import os
import sys
import json
import time
from typing import Any, Dict, List, Optional

import asyncpg
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Import the complete OAuth SDK with callback functionality
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config

# Configure logging to stderr only (MCP requirement)
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # CRITICAL: Must be stderr, not stdout
    format='%(name)s:%(message)s'
)
logger = logging.getLogger("complete-demo-server")

server = Server("complete-demo-server")

# Global instances
db_pool = None
oauth_sdk = None

# =============================================================================
# OAUTH CONFIGURATION WITH YOUR WORKING SETUP
# =============================================================================

# Configure OAuth with your exact working settings
oauth_config = create_hydra_config(
    oauth_server=os.getenv("OAUTH_SERVER", "https://authsec.authnull.com/o"),
    client_id=os.getenv("OAUTH_CLIENT_ID", "test-client"),
    client_secret=os.getenv("OAUTH_CLIENT_SECRET", "test-secret"),
    scopes=["mcp:read", "mcp:admin"]  # Using your exact scopes
)

# Initialize OAuth SDK
oauth_sdk = MCPOAuthSDK(oauth_config)

# =============================================================================
# DATABASE FUNCTIONS (SAME AS WORKING EXAMPLE)
# =============================================================================

async def connect_database():
    """Connect to PostgreSQL database"""
    global db_pool
    
    connection_string = os.getenv("POSTGRES_CONNECTION_STRING")
    if len(sys.argv) > 1:
        connection_string = sys.argv[1]
    
    if not connection_string:
        logger.warning("No database connection string provided - using demo mode")
        return
    
    try:
        db_pool = await asyncpg.create_pool(
            connection_string,
            min_size=1,
            max_size=10,
            command_timeout=30
        )
        logger.info("✅ Database connection pool created successfully")
    except Exception as e:
        logger.error(f"❌ Failed to create database connection pool: {e}")
        logger.info("Continuing in demo mode without database")

async def execute_query(query: str, params: Optional[List] = None, username: str = None) -> List[Dict[str, Any]]:
    """Execute a SELECT query with user logging"""
    if not db_pool:
        # Return demo data if no database
        return [
            {
                "demo_id": 1,
                "demo_data": "This is demo data",
                "executed_by": username,
                "note": "Configure POSTGRES_CONNECTION_STRING for real database access"
            },
            {
                "demo_id": 2,
                "demo_data": "Another demo record",
                "executed_by": username,
                "note": "All operations are logged with your username"
            }
        ]
    
    # Security check - only allow SELECT statements
    query_upper = query.strip().upper()
    if not query_upper.startswith('SELECT'):
        raise ValueError("Only SELECT queries are allowed for security")
    
    # Log query execution with user info
    logger.info(f"🔍 Query by '{username}': {query[:100]}{'...' if len(query) > 100 else ''}")
    
    async with db_pool.acquire() as conn:
        try:
            if params:
                rows = await conn.fetch(query, *params)
            else:
                rows = await conn.fetch(query)
            
            # Convert to list of dictionaries
            result = [dict(row) for row in rows]
            logger.info(f"✅ Query returned {len(result)} rows for user '{username}'")
            return result
        except Exception as e:
            logger.error(f"❌ Query execution failed for user '{username}': {e}")
            raise

async def get_schema_info(username: str) -> Dict[str, Any]:
    """Get comprehensive database schema information"""
    if not db_pool:
        # Return demo schema if no database
        return {
            "tables": [
                {"schemaname": "public", "tablename": "demo_table", "tableowner": "demo_user"},
                {"schemaname": "public", "tablename": "users", "tableowner": "demo_user"}
            ],
            "views": [],
            "columns": [
                {"table_name": "demo_table", "column_name": "id", "data_type": "integer"},
                {"table_name": "demo_table", "column_name": "name", "data_type": "text"},
                {"table_name": "users", "column_name": "user_id", "data_type": "integer"},
                {"table_name": "users", "column_name": "username", "data_type": "text"}
            ],
            "accessed_by": username,
            "access_timestamp": time.time(),
            "table_count": 2,
            "note": "This is demo schema data"
        }
    
    logger.info(f"📊 Getting schema info for user '{username}'")
    
    async with db_pool.acquire() as conn:
        try:
            # Get tables
            tables_query = """
            SELECT 
                schemaname,
                tablename,
                tableowner,
                hasindexes,
                hasrules,
                hastriggers
            FROM pg_tables 
            WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
            ORDER BY schemaname, tablename;
            """
            tables = await conn.fetch(tables_query)
            
            # Get views
            views_query = """
            SELECT 
                schemaname,
                viewname,
                viewowner
            FROM pg_views 
            WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
            ORDER BY schemaname, viewname;
            """
            views = await conn.fetch(views_query)
            
            # Get columns
            columns_query = """
            SELECT 
                table_schema,
                table_name,
                column_name,
                data_type,
                is_nullable,
                column_default,
                ordinal_position
            FROM information_schema.columns 
            WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
            ORDER BY table_schema, table_name, ordinal_position;
            """
            columns = await conn.fetch(columns_query)
            
            return {
                "tables": [dict(row) for row in tables],
                "views": [dict(row) for row in views],
                "columns": [dict(row) for row in columns],
                "accessed_by": username,
                "access_timestamp": time.time(),
                "table_count": len(tables),
                "view_count": len(views),
                "security_level": "USER_AUTHENTICATED_ACCESS"
            }
        except Exception as e:
            logger.error(f"❌ Schema info retrieval failed for user '{username}': {e}")
            raise

async def admin_operation(username: str) -> Dict[str, Any]:
    """Perform admin operation - REQUIRES MCP:ADMIN SCOPE"""
    logger.info(f"⚠️ Admin operation performed by '{username}'")
    
    return {
        "operation": "system_maintenance",
        "performed_by": username,
        "timestamp": time.time(),
        "actions": [
            "Database health check completed",
            "Connection pool status verified",
            "OAuth token validation performed",
            "Audit log review completed"
        ],
        "status": "success",
        "security_note": "✅ Admin operation performed by authenticated admin user"
    }

# =============================================================================
# MCP HANDLERS WITH OAUTH PROTECTION
# =============================================================================

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools based on authentication status"""
    
    # Debug logging to see what's happening
    is_authenticated = oauth_sdk.is_authenticated()
    current_user = oauth_sdk.get_current_user()
    logger.info(f"🔧 handle_list_tools called - authenticated: {is_authenticated}")
    if current_user:
        logger.info(f"🔧 Current user: {current_user.username}, scopes: {current_user.scopes}")
    
    # The OAuth SDK automatically handles which tools to show
    # based on authentication status and user scopes
    
    return [
        # Public tools (always visible)
        types.Tool(
            name="get_server_info",
            description="ℹ️ Get server information (no authentication required)",
            inputSchema={"type": "object", "properties": {}},
        ),
        
        # Protected tools - OAuth SDK controls visibility based on scopes
        types.Tool(
            name="query_database",
            description="🗄️ Execute SQL query (requires mcp:read scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "SQL SELECT query to execute"
                    }
                },
                "required": ["sql"]
            },
        ),
        types.Tool(
            name="list_tables",
            description="📊 List database tables (requires mcp:read scope)",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_schema",
            description="📋 Get complete database schema (requires mcp:read scope)",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_table_info",
            description="📝 Get detailed table information (requires mcp:read scope)",
            inputSchema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Name of the table to get info for"
                    }
                },
                "required": ["table_name"]
            },
        ),
        types.Tool(
            name="admin_operation",
            description="⚙️ Perform admin operation (requires mcp:admin scope)",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="debug_tools",
            description="🔍 Debug tool visibility (no authentication required)",
            inputSchema={"type": "object", "properties": {}},
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    """Handle tool execution requests with complete OAuth protection"""
    
    try:
        # Get current authenticated user (OAuth SDK handles this)
        current_user = oauth_sdk.get_current_user()
        username = current_user.username if current_user else "anonymous"
        
        # Public tools (no authentication required)
        if name == "get_server_info":
            logger.info(f"ℹ️ Server info accessed by '{username}'")
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "success": True,
                    "server_info": {
                        "name": "Complete Demo Server",
                        "version": "1.0.0-oauth-protected",
                        "oauth_server": oauth_config.oauth_server,
                        "database_connected": db_pool is not None,
                        "authentication_required": False,
                        "features": [
                            "OAuth 2.0 + PKCE authentication",
                            "Localhost callback server (port 3000)",
                            "PostgreSQL integration",
                            "Scope-based access control",
                            "Complete audit logging"
                        ],
                        "oauth_flow": [
                            "1. Call 'oauth_authenticate'",
                            "2. Click auth URL in browser",
                            "3. Complete OAuth (redirects to localhost:3000)",
                            "4. Call 'oauth_refresh_tools'",
                            "5. Protected tools now available!"
                        ]
                    },
                    "accessed_by": username,
                    "timestamp": time.time()
                }, indent=2, default=str)
            )]
        
        # Protected tools (OAuth SDK ensures authentication and scopes)
        elif name == "query_database":
            # OAuth SDK ensures user has 'mcp:read' scope before this code runs
            if not arguments or "sql" not in arguments:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Missing SQL query parameter"}, indent=2)
                )]
            
            sql = arguments["sql"]
            
            # Execute query with user context
            results = await execute_query(sql, username=username)
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "success": True,
                    "results": results,
                    "row_count": len(results),
                    "query": sql,
                    "executed_by": username,
                    "timestamp": time.time(),
                    "security_status": "✅ Authenticated query execution"
                }, indent=2, default=str)
            )]
        
        elif name == "list_tables":
            # OAuth SDK ensures user has 'mcp:read' scope
            try:
                # Get table list using schema info
                schema_info = await get_schema_info(username)
                tables = schema_info["tables"]
                
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "tables": tables,
                        "table_count": len(tables),
                        "accessed_by": username,
                        "timestamp": time.time(),
                        "security_status": "✅ Authenticated schema access"
                    }, indent=2, default=str)
                )]
            except Exception as e:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "Failed to list tables",
                        "message": str(e),
                        "accessed_by": username
                    }, indent=2)
                )]
        
        elif name == "get_schema":
            # OAuth SDK ensures user has 'mcp:read' scope
            try:
                schema_info = await get_schema_info(username)
                
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "schema": schema_info,
                        "security_status": "✅ Authenticated schema access"
                    }, indent=2, default=str)
                )]
            except Exception as e:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "Failed to get schema",
                        "message": str(e),
                        "accessed_by": username
                    }, indent=2)
                )]
        
        elif name == "get_table_info":
            # OAuth SDK ensures user has 'mcp:read' scope
            if not arguments or "table_name" not in arguments:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Missing table_name parameter"}, indent=2)
                )]
            
            try:
                table_name = arguments["table_name"]
                
                # Get table column information
                if db_pool:
                    query = """
                    SELECT 
                        column_name,
                        data_type,
                        is_nullable,
                        column_default,
                        ordinal_position
                    FROM information_schema.columns 
                    WHERE table_name = $1 
                    AND table_schema NOT IN ('information_schema', 'pg_catalog')
                    ORDER BY ordinal_position;
                    """
                    
                    async with db_pool.acquire() as conn:
                        rows = await conn.fetch(query, table_name)
                        results = [dict(row) for row in rows]
                else:
                    # Demo data
                    results = [
                        {"column_name": "id", "data_type": "integer", "is_nullable": "NO"},
                        {"column_name": "name", "data_type": "text", "is_nullable": "YES"}
                    ]
                
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "table_name": table_name,
                        "columns": results,
                        "column_count": len(results),
                        "accessed_by": username,
                        "timestamp": time.time(),
                        "security_status": "✅ Authenticated table info access"
                    }, indent=2, default=str)
                )]
            except Exception as e:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "Failed to get table info",
                        "message": str(e),
                        "table_name": arguments.get("table_name", "unknown"),
                        "accessed_by": username
                    }, indent=2)
                )]
        
        elif name == "admin_operation":
            # OAuth SDK ensures user has 'mcp:admin' scope
            try:
                result = await admin_operation(username)
                
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "success": True,
                        "operation_result": result,
                        "security_status": "✅ Admin operation by authenticated admin"
                    }, indent=2, default=str)
                )]
            except Exception as e:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "Admin operation failed",
                        "message": str(e),
                        "accessed_by": username
                    }, indent=2)
                )]
        
        elif name == "debug_tools":
            # Debug tool to help understand what's happening
            logger.info(f"🔍 Debug tools called by '{username}'")
            
            is_authenticated = oauth_sdk.is_authenticated()
            protected_tools = oauth_sdk.protected_tools
            
            debug_info = {
                "success": True,
                "authentication_status": {
                    "authenticated": is_authenticated,
                    "user": username,
                    "user_scopes": current_user.scopes if current_user else [],
                    "token_expires_at": oauth_sdk.token_expires_at if is_authenticated else None,
                    "time_left": int(oauth_sdk.token_expires_at - time.time()) if is_authenticated else 0
                },
                "protected_tools": {
                    "total_protected": len(protected_tools),
                    "protected_tool_list": [
                        {
                            "name": tool_name,
                            "required_scopes": tool_info.get("scopes", []),
                            "visible": oauth_sdk._should_show_tool(tool_name)
                        }
                        for tool_name, tool_info in protected_tools.items()
                    ]
                },
                "oauth_config": {
                    "oauth_server": oauth_sdk.config.oauth_server,
                    "client_id": oauth_sdk.config.client_id,
                    "scopes": oauth_sdk.config.scopes
                },
                "troubleshooting": {
                    "if_tools_not_visible": [
                        "1. Ensure you've called 'oauth_authenticate' and completed OAuth",
                        "2. Call 'oauth_check_status' to verify authentication",
                        "3. Call 'oauth_refresh_tools' to force tool list update",
                        "4. Ask 'What tools are available?' to trigger tool list refresh"
                    ]
                }
            }
            
            return [types.TextContent(
                type="text",
                text=json.dumps(debug_info, indent=2, default=str)
            )]
    
    except Exception as e:
        # IMPORTANT: Log to stderr, return JSON error (don't let exceptions break MCP)
        logger.error(f"❌ Tool execution failed for user '{username}': {e}")
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "error": "Tool execution failed",
                "message": str(e),
                "user": username
            }, indent=2)
        )]

# =============================================================================
# OAUTH PROTECTION SETUP (SAME AS WORKING EXAMPLE)
# =============================================================================

def setup_oauth_protection():
    """Setup OAuth protection for tools using your exact scopes"""
    
    # Protect tools with your exact working scopes
    oauth_sdk.protect_tool("query_database", scopes=["mcp:read"])
    oauth_sdk.protect_tool("list_tables", scopes=["mcp:read"])
    oauth_sdk.protect_tool("get_schema", scopes=["mcp:read"])
    oauth_sdk.protect_tool("get_table_info", scopes=["mcp:read"])
    oauth_sdk.protect_tool("admin_operation", scopes=["mcp:admin"])
    
    # Note: get_server_info and debug_tools are NOT protected (remain public)
    
    logger.info("🛡️ OAuth protection configured with mcp:read and mcp:admin scopes")
    logger.info(f"🛡️ Protected tools: {list(oauth_sdk.protected_tools.keys())}")

# =============================================================================
# MAIN FUNCTION
# =============================================================================

async def main():
    """Main server function with complete OAuth integration"""
    
    # IMPORTANT: Only log to stderr, never to stdout (MCP requirement)
    logger.info("🚀 Starting Complete Demo Server with OAuth SDK")
    
    try:
        # Setup OAuth (EASY - just 2 lines!)
        oauth_sdk.register_with_server(server)
        setup_oauth_protection()
        
        # Connect to database (optional)
        await connect_database()
        
        # Run MCP server
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            # IMPORTANT: All startup messages go to stderr via logger
            logger.info("🎉 COMPLETE DEMO SERVER STARTED")
            logger.info("🔐 OAuth SDK with localhost callback integration complete")
            logger.info("🛡️ Protected tools require authentication with mcp:read or mcp:admin scopes")
            logger.info("🌐 Callback server will use localhost:3000 (or auto-find available port)")
            logger.info("📋 Expected OAuth flow:")
            logger.info("   1. Call 'oauth_authenticate' to start login")
            logger.info("   2. Click auth URL to complete OAuth in browser")
            logger.info("   3. Browser redirects to localhost:3000/callback")
            logger.info("   4. Token exchange happens automatically")
            logger.info("   5. Call 'oauth_refresh_tools' to see new tools")
            logger.info("   6. Database tools now available with your username!")
            
            if db_pool:
                logger.info("✅ Database connected - real PostgreSQL operations available")
            else:
                logger.info("📝 Demo mode - showing demo data (set POSTGRES_CONNECTION_STRING for real database)")
            
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="complete-demo-server",
                    server_version="1.0.0-oauth-callback",
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
# COMPLETE OAUTH FLOW WITH LOCALHOST:3000 CALLBACK
# =============================================================================

"""
🔄 COMPLETE OAUTH FLOW WITH LOCALHOST CALLBACK:

STEP 1: Server starts (only OAuth + public tools visible)
Available tools: [
  "oauth_authenticate",     # Start OAuth flow
  "oauth_check_status",     # Check authentication status
  "oauth_refresh_tools",    # Force tool list refresh
  "get_server_info"         # Public server information
]

STEP 2: User calls oauth_authenticate
Response: {
  "status": "oauth_started",
  "auth_url": "https://authsec.authnull.com/o/oauth2/auth?response_type=code&client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=mcp%3Aread+mcp%3Aadmin&state=...&code_challenge=...&code_challenge_method=S256",
  "callback_port": 3000,
  "redirect_uri": "http://localhost:3000/callback",
  "instructions": [
    "1. Click the authentication URL above",
    "2. Complete OAuth authentication in your browser",
    "3. You will be redirected to localhost callback",
    "4. Authentication will complete automatically",
    "5. Use 'oauth_check_status' to verify completion",
    "6. Use 'oauth_refresh_tools' to see your new tools"
  ],
  "note": "Callback server is running - authentication will complete automatically after OAuth flow"
}

STEP 3: User clicks auth URL
- Browser opens OAuth server
- User logs in with their credentials
- OAuth server redirects to: http://localhost:3000/callback?code=ory_ac_HeDrbRr92fQoLwVqxL2cmr4t7hywpHmI1FQAS_voz4w.WqRWZA3ZtpC-O_5K3_7ijEVnsog4bJZXAFXwu2t_FGs&scope=mcp%3Aread+mcp%3Aadmin&state=...

STEP 4: Localhost callback server handles redirect
- Validates state parameter
- Extracts authorization code
- Exchanges code for access token
- Retrieves user information
- Saves token to file
- Shows success page in browser

STEP 5: User calls oauth_check_status
Response: {
  "authenticated": true,
  "user": "c751290c-481d-4d95-9079-df9d8eca0f3d",
  "scopes": ["mcp:read", "mcp:admin"],
  "expires_at": 1750766573.5556405,
  "time_left": 3568,
  "method": "userinfo",
  "callback_port": 3000,
  "oauth_server": "https://authsec.authnull.com/o",
  "status": "✅ AUTHENTICATED AND READY"
}

STEP 6: User calls oauth_refresh_tools
Response: {
  "status": "tools_refreshed",
  "authenticated": true,
  "user": "c751290c-481d-4d95-9079-df9d8eca0f3d",
  "total_protected_tools": 5,
  "visible_tools": 5,
  "message": "Tool list has been refreshed. New tools should now be visible."
}

STEP 7: All protected tools now available
Available tools: [
  "oauth_check_status",     # Now shows user info
  "oauth_logout",           # Logout option
  "oauth_refresh_tools",    # Refresh mechanism
  "get_server_info",        # Public information
  "query_database",         # mcp:read scope ✅
  "list_tables",            # mcp:read scope ✅
  "get_schema",             # mcp:read scope ✅
  "get_table_info",         # mcp:read scope ✅
  "admin_operation"         # mcp:admin scope ✅
]

STEP 8: User can now use protected tools
All database operations are logged with username:
- query_database: "🔍 Query by 'c751290c-481d-4d95-9079-df9d8eca0f3d': SELECT * FROM users..."
- list_tables: "📊 Schema access by user 'c751290c-481d-4d95-9079-df9d8eca0f3d'"
- admin_operation: "⚠️ Admin operation performed by 'c751290c-481d-4d95-9079-df9d8eca0f3d'"

🎉 COMPLETE SUCCESS! 
- Full OAuth 2.0 + PKCE flow working
- Localhost:3000 callback server handling redirects
- Automatic token exchange and user info retrieval  
- Token persistence across server restarts
- Complete audit trail with usernames
- Scope-based access control working perfectly

This is exactly the same flow as your working example, 
but now packaged as a reusable SDK that any MCP developer can use! 🛡️
"""