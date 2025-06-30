# 🛡️ Universal MCP OAuth SDK

**Add enterprise-grade OAuth authentication to ANY MCP server in just 3 lines of code!**

This OAuth SDK provides complete OAuth 2.0 + PKCE authentication for Model Context Protocol (MCP) servers with automatic tool protection, scope-based access control, and localhost callback handling.

## ✨ Features

- 🔐 **Complete OAuth 2.1 + PKCE flow** with automatic token exchange
- 🌐 **Localhost callback server** (auto port detection, defaults to 3000)
- 🛡️ **Tool protection** with scope-based access control
- 💾 **Token persistence** across server restarts
- 🔄 **Dynamic tool refresh** - tools appear/disappear based on authentication
- 📋 **Universal compatibility** - works with ANY MCP server
- 🏢 **Multi-provider support** - Hydra
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
pip install aiohttp asyncio
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
```python
from mcp_oauth_sdk import OAuthConfig

oauth_config = OAuthConfig(
    oauth_server="https://your-custom-oauth-server.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scopes=["custom:read", "custom:write", "custom:admin"]
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
# Protect file operations by scope
oauth_sdk.protect_tool("read_file", scopes=["files:read"])
oauth_sdk.protect_tool("write_file", scopes=["files:write"])  
oauth_sdk.protect_tool("delete_file", scopes=["files:admin"])
oauth_sdk.protect_tool("list_files", scopes=["files:read"])

# Result: Users only see tools matching their permissions!
```

### API Gateway MCP
```python
# Different API access levels
oauth_sdk.protect_tool("call_public_api", scopes=[])  # Any authenticated user
oauth_sdk.protect_tool("call_partner_api", scopes=["partner"])
oauth_sdk.protect_tool("call_internal_api", scopes=["internal"])
oauth_sdk.protect_tool("admin_api", scopes=["admin"])
```

### Database MCP (Your Example)
```python
# Read vs Write vs Admin operations
oauth_sdk.protect_tool("query_database", scopes=["db:read"])
oauth_sdk.protect_tool("execute_procedure", scopes=["db:write"])
oauth_sdk.protect_tool("admin_operation", scopes=["db:admin"])
oauth_sdk.protect_tool("backup_database", scopes=["db:admin"])
```

### Multi-Tenant SaaS MCP
```python
# Tenant-specific access
oauth_sdk.protect_tool("tenant_data", scopes=["tenant:read"])
oauth_sdk.protect_tool("tenant_config", scopes=["tenant:admin"])
oauth_sdk.protect_tool("billing_info", scopes=["billing:read"])
oauth_sdk.protect_tool("system_admin", scopes=["system:admin"])
```

## 🔍 Debugging & Troubleshooting

### Enable Debug Mode
```python
import logging
logging.getLogger("mcp-oauth-sdk").setLevel(logging.DEBUG)
```

### Check Authentication Status
```python
# In your tool handler
if oauth_sdk.is_authenticated():
    user = oauth_sdk.get_current_user()
    print(f"User: {user.username}, Scopes: {user.scopes}")
else:
    print("User not authenticated")
```

### Debug Tool Visibility
Add a debug tool to your server:
```python
@server.list_tools()
async def list_tools():
    tools = []
    
    # Add debug tool
    tools.append(types.Tool(
        name="debug_oauth",
        description="🔍 Debug OAuth status and tool visibility",
        inputSchema={"type": "object", "properties": {}}
    ))
    
    # Your other tools...
    return tools

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "debug_oauth":
        return [types.TextContent(
            type="text", 
            text=json.dumps({
                "authenticated": oauth_sdk.is_authenticated(),
                "user": oauth_sdk.get_current_user().username if oauth_sdk.is_authenticated() else None,
                "protected_tools": list(oauth_sdk.protected_tools.keys()),
                "visible_tools": [tool for tool in oauth_sdk.protected_tools.keys() 
                                if oauth_sdk._should_show_tool(tool)]
            }, indent=2)
        )]
```

## 🔧 Advanced Configuration

### Custom Port Range
```python
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

oauth_config = create_hydra_config(
    oauth_server=os.getenv("OAUTH_SERVER", "https://default-oauth.com"),
    client_id=os.getenv("OAUTH_CLIENT_ID"),
    client_secret=os.getenv("OAUTH_CLIENT_SECRET"), 
    scopes=os.getenv("OAUTH_SCOPES", "read,write").split(",")
)
```

## 🌐 OAuth Provider Setup

### Setting Up Ory Hydra
1. **Create OAuth Client:**
   ```bash
   hydra create client \
     --endpoint https://your-hydra-admin.com \
     --client-id your-client-id \
     --client-secret your-client-secret \
     --response-types code \
     --grant-types authorization_code,refresh_token \
     --scope read,write,admin \
     --callbacks http://localhost:3000/callback
   ```

2. **Configure Scopes:**
   ```yaml
   # hydra.yml
   oauth2:
     scopes:
       read: "Read access to resources"
       write: "Write access to resources" 
       admin: "Administrative access"
   ```

### Setting Up Auth0
1. **Create Application** in Auth0 Dashboard
2. **Application Type:** Regular Web Application
3. **Allowed Callback URLs:** `http://localhost:3000/callback`
4. **Grant Types:** Authorization Code, Refresh Token
5. **Add Custom Scopes** in Auth0 API settings

### Setting Up Google OAuth
1. **Google Cloud Console** → APIs & Services → Credentials
2. **Create OAuth 2.0 Client ID**
3. **Application Type:** Web Application
4. **Authorized Redirect URIs:** `http://localhost:3000/callback`

## 📊 Production Considerations

### Security
- ✅ Always use HTTPS in production OAuth servers
- ✅ Use strong client secrets (OAuth SDK handles PKCE automatically)
- ✅ Implement proper scope validation in your OAuth provider
- ✅ Monitor token expiration and refresh flows
- ✅ Use secure token storage (OAuth SDK handles this)

### Scalability
- ✅ OAuth SDK is stateless after authentication
- ✅ Tokens are stored locally per server instance
- ✅ Multiple MCP servers can use the same OAuth provider
- ✅ No database required for OAuth SDK operation

### Monitoring
```python
# Add metrics to your tools
@server.call_tool()
async def call_tool(name: str, arguments: dict):
    user = oauth_sdk.get_current_user()
    username = user.username if user else "anonymous"
    
    # Log all tool usage with user context
    logger.info(f"Tool '{name}' called by user '{username}'")
    
    # Your existing tool logic...
```

## 🎯 Migration Guide

### From No Auth to OAuth SDK
1. **Install OAuth SDK** (no changes to existing tools needed!)
2. **Add 3 lines** to register OAuth SDK
3. **Protect sensitive tools** with `oauth_sdk.protect_tool()`
4. **Test flow** with `oauth_authenticate`
5. **Deploy!** All existing tools work unchanged

### From Custom Auth to OAuth SDK
1. **Remove your custom auth code**
2. **Replace with OAuth SDK** (much simpler!)
3. **Map your old scopes** to OAuth scopes
4. **Update tool protection** to use `oauth_sdk.protect_tool()`
5. **Users get professional OAuth flow** instead of custom auth

## ❓ FAQ

**Q: Does this work with any MCP server?**
A: Yes! 100% universal. Works with database servers, file servers, API gateways, custom tools, anything.

**Q: Do I need to change my existing tool handlers?**
A: No! OAuth SDK works transparently. Your existing `@server.call_tool()` handlers work unchanged.

**Q: What if my OAuth provider uses different endpoints?**
A: OAuth SDK tries multiple common endpoints automatically. For custom providers, just specify the full URLs in `OAuthConfig`.

**Q: Can I use multiple OAuth providers?**
A: Currently one provider per server instance. For multiple providers, run separate MCP server instances.

**Q: What happens if OAuth server is down?**
A: Existing authenticated users continue working. New users see "OAuth server unavailable" message. Server stays operational.

**Q: How do I handle token refresh?**
A: OAuth SDK handles refresh automatically. Tokens are refreshed transparently before expiration.

**Q: Can I customize the OAuth flow UI?**
A: The OAuth provider controls the auth UI. The callback success/error pages can be customized in the SDK.

**Q: Does this support SSO?**
A: Yes! If your OAuth provider supports SSO (like Auth0, Okta), users get seamless SSO experience.

## 🔄 Complete Integration Example

Here's a complete example of adding OAuth to any MCP server:

```python
import asyncio
import json
from typing import List

from mcp.server import Server
from mcp.server.models import InitializationOptions  
import mcp.types as types
import mcp.server.stdio

# Import OAuth SDK
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config

# Create your MCP server as normal
server = Server("my-awesome-server")

# ADD OAUTH (3 lines!)
oauth_config = create_hydra_config("https://oauth.company.com", "client-id", "secret")
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
            description="Get user-specific data (auth required)",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="admin_operation",
            description="Perform admin operation (admin scope required)", 
            inputSchema={"type": "object", "properties": {}}
        )
    ]

# Protect the tools you want
oauth_sdk.protect_tool("user_data", scopes=["read"])
oauth_sdk.protect_tool("admin_operation", scopes=["admin"])
# public_info stays unprotected

# Your existing tool handlers work unchanged!
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> List[types.TextContent]:
    if name == "public_info":
        return [types.TextContent(type="text", text="This is public information")]
    
    elif name == "user_data":
        # OAuth SDK ensures user is authenticated with "read" scope
        user = oauth_sdk.get_current_user()
        return [types.TextContent(
            type="text", 
            text=f"Secret user data for {user.username}"
        )]
    
    elif name == "admin_operation":
        # OAuth SDK ensures user is authenticated with "admin" scope
        user = oauth_sdk.get_current_user()
        return [types.TextContent(
            type="text",
            text=f"Admin operation performed by {user.username}"
        )]

# Run server as normal
async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
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

## 🏆 Result

**Before OAuth SDK:** Anyone can use all tools, no security, no audit trail
**After OAuth SDK:** Enterprise-grade security with 3 lines of code! 

- ✅ Users must authenticate via professional OAuth flow
- ✅ Tools appear/disappear based on user permissions  
- ✅ Complete audit trail with usernames
- ✅ Scope-based access control
- ✅ Zero changes to existing tool code
- ✅ Production-ready security

**Transform any MCP server into an enterprise-ready authenticated service in minutes!** 🚀

---

