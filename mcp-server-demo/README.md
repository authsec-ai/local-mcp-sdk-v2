# 🛡️ Universal MCP OAuth SDK

**Add enterprise-grade OAuth authentication to ANY MCP server in just 3 lines of code!**

This OAuth SDK provides complete OAuth 2.0 + PKCE authentication for Model Context Protocol (MCP) servers with automatic tool protection, scope-based access control, and localhost callback handling.

## ✨ Features

- 🔐 **Complete OAuth 2.1 + PKCE flow** with automatic token exchange
- 🌐 **Localhost callback server** (auto port detection, defaults to 3000)
- 🛡️ **Dynamic tool protection** with scope-based access control
- 💾 **Token persistence** across server restarts
- 🔄 **Dynamic tool refresh** - tools appear/disappear based on authentication
- 📋 **Universal compatibility** - works with ANY MCP server
- 🏢 **Multi-provider support** - Hydra, Auth0, Google, GitHub, Custom
- 📝 **Complete audit logging** - all actions logged with usernames
- ⚡ **Zero configuration** for most OAuth providers

## 🎯 Why Use This?

### Before OAuth SDK:
```
❌ No authentication - anyone can use your tools
❌ No user tracking - don't know who did what
❌ No access control - all tools available to everyone
❌ Security nightmare for production systems
```

### After OAuth SDK:
```
✅ Secure authentication required for protected tools
✅ Complete audit trail with usernames
✅ Scope-based access control (read/admin/custom)
✅ Enterprise-ready security
✅ Professional user experience with browser OAuth flow
```

## 🚀 Quick Start (3 Lines of Code!)

### 1. Install Dependencies
```bash
pip install uv  # or your specific dependencies
```
```bash
uv add aiohttp asyncpg  # or your specific dependencies
```

### 2. Add OAuth to Your MCP Server
```python
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config

# Your existing MCP server code...
server = Server("my-awesome-server")

# ADD THESE 3 LINES:
oauth_config = create_hydra_config("https://your-oauth-server.com", "client-id", "client-secret")
oauth_sdk = MCPOAuthSDK(oauth_config)
oauth_sdk.register_with_server(server)

# Protect any tools you want:
oauth_sdk.protect_tool("sensitive_operation", scopes=["admin"])
oauth_sdk.protect_tool("read_data", scopes=["read"])

# Your existing tool handlers work unchanged!
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict):
    if name == "sensitive_operation":
        # OAuth SDK automatically ensures user is authenticated with "admin" scope
        user = oauth_sdk.get_current_user()
        return f"Admin operation by {user.username}"
    # ... rest of your existing code
```

**That's it!** Your MCP server now has enterprise OAuth authentication! 🎉

## 🔄 User Experience Flow

### Step 1: Unauthenticated State
```
Available tools:
├── oauth_authenticate        # Start login
├── oauth_check_status       # See auth status
├── oauth_refresh_tools      # Refresh tool list
└── public_tools...          # Any unprotected tools
```

### Step 2: User Starts Authentication
```bash
# User calls oauth_authenticate
→ Returns auth URL: https://oauth-server.com/oauth2/auth?...
→ User clicks URL in browser
→ Completes OAuth on your OAuth provider
→ Browser redirects to localhost:3000/callback
→ Token exchange happens automatically
→ Success page shows in browser
```

### Step 3: Authenticated State
```
Available tools:
├── oauth_check_status       # Now shows user info
├── oauth_logout            # Logout option
├── oauth_refresh_tools     # Refresh mechanism
├── public_tools...         # Unprotected tools
└── protected_tools...      # 🔓 NOW VISIBLE!
    ├── admin_operation     # (requires admin scope)
    ├── read_data          # (requires read scope)
    └── user_specific_tool # (requires user scope)
```

## 🔧 Configuration Examples

### Ory Hydra (Most Common)
```python
from mcp_oauth_sdk import create_hydra_config

oauth_config = create_hydra_config(
    oauth_server="https://your-hydra-server.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scopes=["read", "admin"]  # Your custom scopes
)
```


## 🛡️ Tool Protection Patterns

### Basic Protection
```python
# Protect with single scope
oauth_sdk.protect_tool("read_database", scopes=["read"])

# Protect with multiple scopes (user needs ANY of them)
oauth_sdk.protect_tool("admin_operation", scopes=["admin", "superuser"])

# Protect with authentication only (no specific scopes)
oauth_sdk.protect_tool("user_profile", scopes=[])

# Leave tools unprotected (public access)
# oauth_sdk.protect_tool("public_info")  # Don't call this = public tool
```

### Advanced Protection with Decorator
```python
from mcp_oauth_sdk import oauth_required

@oauth_required(oauth_sdk, scopes=["admin"])
async def sensitive_function():
    user = oauth_sdk.get_current_user()
    return f"Admin action by {user.username}"
```

### Dynamic Scope Checking
```python
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict):
    if name == "flexible_tool":
        user = oauth_sdk.get_current_user()
        if user and "admin" in user.scopes:
            # Admin gets full access
            return admin_response()
        elif user and "read" in user.scopes:
            # Read-only users get limited access
            return readonly_response()
        else:
            # Unauthenticated users get public data
            return public_response()
```

## 📋 Real-World Examples

### File Server MCP
```python
from mcp.server import Server
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config
import mcp.types as types

server = Server("file-server")

# Add OAuth
oauth_config = create_hydra_config("https://oauth.company.com", "file-client", "secret")
oauth_sdk = MCPOAuthSDK(oauth_config)
oauth_sdk.register_with_server(server)

# Protect file operations by scope
oauth_sdk.protect_tool("read_file", scopes=["files:read"])
oauth_sdk.protect_tool("write_file", scopes=["files:write"])  
oauth_sdk.protect_tool("delete_file", scopes=["files:admin"])
oauth_sdk.protect_tool("list_files", scopes=["files:read"])
# "get_public_info" stays unprotected

@server.list_tools()
async def list_tools():
    return [
        types.Tool(name="get_public_info", description="Public file server info"),
        types.Tool(name="list_files", description="List files (read access)"),
        types.Tool(name="read_file", description="Read file content (read access)"),
        types.Tool(name="write_file", description="Write file (write access)"),
        types.Tool(name="delete_file", description="Delete file (admin access)")
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    user = oauth_sdk.get_current_user()
    username = user.username if user else "anonymous"
    
    if name == "read_file":
        # User is guaranteed to have "files:read" scope
        filename = arguments["filename"]
        content = read_file_from_disk(filename)
        log_action(f"File '{filename}' read by {username}")
        return [types.TextContent(type="text", text=content)]
    
    # ... other handlers
```

**Result:** Users only see file tools matching their permissions!

### Database MCP (Like Your Example)
```python
from mcp.server import Server
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config

server = Server("database-server")

# Add OAuth (same as your working config)
oauth_config = create_hydra_config(
    oauth_server="https://authsec.authnull.com/o",
    client_id="test-client",
    client_secret="test-secret",
    scopes=["mcp:read", "mcp:admin"]
)
oauth_sdk = MCPOAuthSDK(oauth_config)
oauth_sdk.register_with_server(server)

# Protect database operations
oauth_sdk.protect_tool("execute_query", scopes=["mcp:read"])
oauth_sdk.protect_tool("get_schema", scopes=["mcp:read"])
oauth_sdk.protect_tool("export_data", scopes=["mcp:read"])
oauth_sdk.protect_tool("backup_database", scopes=["mcp:admin"])
oauth_sdk.protect_tool("admin_maintenance", scopes=["mcp:admin"])
# "get_server_info" stays public

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "execute_query":
        # User guaranteed to have mcp:read scope
        user = oauth_sdk.get_current_user()
        sql = arguments["query"]
        results = await execute_safe_query(sql, username=user.username)
        return [types.TextContent(type="text", text=json.dumps(results))]
    
    # ... other handlers work unchanged
```

### API Gateway MCP
```python
# Different API access levels
oauth_sdk.protect_tool("call_public_api", scopes=[])  # Any authenticated user
oauth_sdk.protect_tool("call_partner_api", scopes=["partner"])
oauth_sdk.protect_tool("call_internal_api", scopes=["internal"])
oauth_sdk.protect_tool("admin_api", scopes=["admin"])

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "call_internal_api":
        # User guaranteed to have "internal" scope
        user = oauth_sdk.get_current_user()
        response = await call_internal_service(arguments, user_context=user.username)
        return [types.TextContent(type="text", text=response)]
```

### Multi-Tenant SaaS MCP
```python
# Tenant-specific access
oauth_sdk.protect_tool("tenant_data", scopes=["tenant:read"])
oauth_sdk.protect_tool("tenant_config", scopes=["tenant:admin"])
oauth_sdk.protect_tool("billing_info", scopes=["billing:read"])
oauth_sdk.protect_tool("system_admin", scopes=["system:admin"])

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "tenant_data":
        user = oauth_sdk.get_current_user()
        tenant_id = extract_tenant_from_user(user)
        data = get_tenant_data(tenant_id, user.username)
        return [types.TextContent(type="text", text=json.dumps(data))]
```

## 🔍 Debugging & Troubleshooting

### Enable Debug Mode
```python
import logging
logging.getLogger("mcp-oauth-sdk").setLevel(logging.DEBUG)
```

### Add Debug Tool to Your Server
```python
@server.list_tools()
async def list_tools():
    tools = [
        # Your normal tools...
        types.Tool(
            name="debug_oauth",
            description="🔍 Debug OAuth status and tool visibility",
            inputSchema={"type": "object", "properties": {}}
        )
    ]
    return tools

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "debug_oauth":
        return [types.TextContent(
            type="text", 
            text=json.dumps({
                "authenticated": oauth_sdk.is_authenticated(),
                "user": oauth_sdk.get_current_user().username if oauth_sdk.is_authenticated() else None,
                "user_scopes": oauth_sdk.get_current_user().scopes if oauth_sdk.is_authenticated() else [],
                "protected_tools": list(oauth_sdk.protected_tools.keys()),
                "visible_protected_tools": [
                    tool for tool in oauth_sdk.protected_tools.keys() 
                    if oauth_sdk._should_show_tool(tool)
                ],
                "total_tools_in_system": "Check with 'What tools are available?'"
            }, indent=2)
        )]
    
    # Your other tool handlers...
```

### Check Authentication Status in Code
```python
# In your tool handler
if oauth_sdk.is_authenticated():
    user = oauth_sdk.get_current_user()
    print(f"User: {user.username}, Scopes: {user.scopes}")
else:
    print("User not authenticated")
```

## 🔧 Advanced Configuration

### Custom Port Range
```python
from mcp_oauth_sdk import OAuthConfig

oauth_config = OAuthConfig(
    oauth_server="https://oauth.company.com",
    client_id="client-id",
    client_secret="client-secret", 
    scopes=["read", "write"],
    redirect_port_range=(8000, 8010)  # Use ports 8000-8010 instead of 3000-3020
)
```

### Custom Token Storage
```python
oauth_config = OAuthConfig(
    oauth_server="https://oauth.company.com",
    client_id="client-id", 
    client_secret="client-secret",
    scopes=["read", "write"],
    token_file_name="my_app_oauth_token.json"  # Custom token file name
)
```

### Environment Variables
```python
import os
from mcp_oauth_sdk import create_hydra_config

oauth_config = create_hydra_config(
    oauth_server=os.getenv("OAUTH_SERVER", "https://default-oauth.com"),
    client_id=os.getenv("OAUTH_CLIENT_ID"),
    client_secret=os.getenv("OAUTH_CLIENT_SECRET"), 
    scopes=os.getenv("OAUTH_SCOPES", "read,write").split(",")
)
```

### Claude Desktop Configuration
```json
{
  "mcpServers": {
    "your-server": {
      "command": "python",
      "args": ["your_server.py"],
      "env": {
        "OAUTH_SERVER": "https://your-oauth-server.com",
        "OAUTH_CLIENT_ID": "your-client-id",
        "OAUTH_CLIENT_SECRET": "your-client-secret",
        "DATABASE_URL": "your-database-connection"
      }
    }
  }
}
```

Here's a complete example of adding OAuth to any MCP server:

```python
import asyncio
import json
import logging
from typing import List

from mcp.server import Server
from mcp.server.models import InitializationOptions  
import mcp.types as types
import mcp.server.stdio

# Import OAuth SDK
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config

# Configure logging
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("my-server")

# Create your MCP server as normal
server = Server("my-awesome-server")

# ADD OAUTH (3 lines!)
oauth_config = create_hydra_config(
    oauth_server="https://oauth.company.com", 
    client_id="your-client-id", 
    client_secret="your-secret",
    scopes=["read", "write", "admin"]
)
oauth_sdk = MCPOAuthSDK(oauth_config)
oauth_sdk.register_with_server(server)

# Define your tools as normal
@server.list_tools()
async def list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name="public_info",
            description="Get public information (no auth required)",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="user_data", 
            description="Get user-specific data (read scope required)",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="modify_data",
            description="Modify data (write scope required)",
            inputSchema={
                "type": "object", 
                "properties": {
                    "data": {"type": "string", "description": "Data to modify"}
                },
                "required": ["data"]
            }
        ),
        types.Tool(
            name="admin_operation",
            description="Perform admin operation (admin scope required)", 
            inputSchema={"type": "object", "properties": {}}
        )
    ]

# Protect the tools you want
oauth_sdk.protect_tool("user_data", scopes=["read"])
oauth_sdk.protect_tool("modify_data", scopes=["write"])
oauth_sdk.protect_tool("admin_operation", scopes=["admin"])
# public_info stays unprotected

# Your existing tool handlers work unchanged!
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> List[types.TextContent]:
    # Get user context (None if not authenticated)
    user = oauth_sdk.get_current_user()
    username = user.username if user else "anonymous"
    
    if name == "public_info":
        logger.info(f"Public info accessed by {username}")
        return [types.TextContent(
            type="text", 
            text=json.dumps({
                "message": "This is public information",
                "accessed_by": username,
                "requires_auth": False
            })
        )]
    
    elif name == "user_data":
        # OAuth SDK ensures user is authenticated with "read" scope
        logger.info(f"User data accessed by {user.username}")
        return [types.TextContent(
            type="text", 
            text=json.dumps({
                "message": f"Secret user data for {user.username}",
                "user_scopes": user.scopes,
                "requires_auth": True,
                "required_scopes": ["read"]
            })
        )]
    
    elif name == "modify_data":
        # OAuth SDK ensures user is authenticated with "write" scope
        data = arguments.get("data", "")
        logger.info(f"Data modified by {user.username}: {data}")
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "message": f"Data '{data}' modified by {user.username}",
                "operation": "modify",
                "requires_auth": True,
                "required_scopes": ["write"]
            })
        )]
    
    elif name == "admin_operation":
        # OAuth SDK ensures user is authenticated with "admin" scope
        logger.info(f"Admin operation performed by {user.username}")
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "message": f"Admin operation performed by {user.username}",
                "operation": "admin",
                "requires_auth": True,
                "required_scopes": ["admin"],
                "elevated_privileges": True
            })
        )]
    
    else:
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": f"Unknown tool: {name}"})
        )]

# Run server as normal
async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        logger.info("🚀 Server starting with OAuth authentication")
        await server.run(
            read_stream,
            write_stream, 
            InitializationOptions(
                server_name="my-awesome-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())
```

