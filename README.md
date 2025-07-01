MCP OAuth SDK for Dynamic Server Integration
This SDK (mcp_oauth_sdk.py) provides a robust and reusable solution for integrating OAuth 2.0 authentication into any Model Context Protocol (MCP) server. It's designed to dynamically discover and protect the tools defined by your MCP application, making it easy to add secure, scope-based access control without tightly coupling the authentication logic to your specific server implementation.

What is this SDK for?
If you are building an MCP server and need to add:

OAuth 2.1 authentication.

Fine-grained, scope-based access control to your tools.

Automatic discovery of your application's tools by the authentication layer.

A clear separation between authentication concerns and your core MCP logic.

...then this SDK is for you.

Key Features of the SDK
Flexible OAuth 2.1 Configuration: Configure your OAuth provider.

Dynamic Tool Discovery: The SDK automatically identifies and registers the tools your MCP server exposes, adapting to changes in your tool definitions without requiring SDK modifications.

Seamless Tool Protection: Easily protect specific tools with required OAuth scopes. The SDK handles access checks before dispatching tool calls.

Authentication Flow Management: Provides tools for initiating OAuth flows, handling callbacks, checking authentication status, and logging out.

Persistence: Automatically saves and loads authentication tokens for persistent sessions.

Prerequisites for Integration
To integrate this SDK into your MCP server, you need:

Python 3.8+

aiohttp: For handling HTTP requests and the OAuth callback server.

mcp-server: The core Model Context Protocol server library.


Installation
Obtain the SDK:
Copy the mcp_oauth_sdk.py file into your MCP server project directory.

Install Python dependencies:

pip install uv
uv add aiohttp mcp-server

Integration Guide: How to Use the SDK in Your MCP Server
To integrate mcp_oauth_sdk.py into your MCP server, follow these steps:

Step 1: Define Your MCP Server's Contract
Your MCP server must adhere to a simple contract for the SDK to dynamically interact with its tools:

Tool Definition Function (define_application_tools):
Create a function named define_application_tools() that returns a List[mcp.types.Tool]. This function should enumerate all the tools your MCP server provides.

# In your_mcp_server_main_file.py (e.g., main.py)
import mcp.types as types
from typing import List

def define_application_tools() -> List[types.Tool]:
    """
    Defines all the tools provided by this MCP server application.
    The OAuth SDK will dynamically discover these tools.
    """
    return [
        types.Tool(
            name="my_public_tool",
            description="A tool accessible to everyone.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="my_protected_read_tool",
            description="A tool requiring 'my_app:read' scope.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="my_protected_admin_tool",
            description="A tool requiring 'my_app:admin' scope.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # ... add all your application's tools here
    ]

Tool Call Handler Function (handle_application_tool_call):
Create an async function named handle_application_tool_call(name: str, arguments: dict | None) that will be responsible for executing the logic of your application's tools. The OAuth SDK will delegate all non-OAuth tool calls to this function.

# In your_mcp_server_main_file.py (e.g., main.py)
import json
# ... other imports (e.g., your database logic, random, etc.)

async def handle_application_tool_call(name: str, arguments: dict | None) -> List[types.TextContent]:
    """
    Handles the execution of application-specific tools.
    The OAuth SDK will call this function for non-OAuth tools.
    """
    # You'll need access to the oauth_sdk instance here to get the current user
    # A common pattern is to make oauth_sdk a global variable or pass it around.
    # For this example, let's assume 'oauth_sdk' is globally accessible.
    current_user = oauth_sdk.get_current_user() # Assuming oauth_sdk is global
    username = current_user.username if current_user else "anonymous"

    if name == "my_public_tool":
        return [types.TextContent(type="text", text=f"This is a public response from {username}.")]
    elif name == "my_protected_read_tool":
        return [types.TextContent(type="text", text=f"Sensitive data accessed by {username}.")]
    elif name == "my_protected_admin_tool":
        return [types.TextContent(type="text", text=f"Admin action performed by {username}.")]
    else:
        return [types.TextContent(type="text", text=json.dumps({"error": f"Unknown application tool: {name}"}))]

Important: Ensure oauth_sdk is accessible within handle_application_tool_call. Making it a global variable (as in the main.py example) is a common pattern for MCP servers.


Step 2: Initialize and Register the SDK in Your Main Server File
In your MCP server's main entry point file (e.g., main.py or your_mcp_server.py):

Import necessary components:

# your_mcp_server_main_file.py
import asyncio
import logging
import sys
import os # Needed for environment variables
from typing import List, Dict, Any

import mcp.types as types
from mcp.server import Server, NotificationOptions
import mcp.server.stdio

# Import the SDK and your application's tool functions
from mcp_oauth_sdk import MCPOAuthSDK, create_hydra_config # Or create_auth0_config, etc.
# Assuming define_application_tools and handle_application_tool_call are in this file
# If they are in another file, import them from there:
# from .your_tool_definitions_module import define_application_tools, handle_application_tool_call

Initialize your MCP Server and the OAuth SDK:

# your_mcp_server_main_file.py
logger = logging.getLogger("your-mcp-server")
server = Server("your-mcp-server-id")

# Initialize the OAuth SDK. It will automatically read config from environment variables.
# You can also pass an OAuthConfig object explicitly if you prefer:
# my_oauth_config = create_hydra_config(
#     oauth_server=os.getenv("OAUTH_SERVER", "default_server_url"),
#     client_id=os.getenv("OAUTH_CLIENT_ID", "default_client_id"),
#     client_secret=os.getenv("OAUTH_CLIENT_SECRET", "default_client_secret"),
#     scopes=os.getenv("OAUTH_SCOPES", "default:scope").split()
# )
# oauth_sdk = ProductionMCPOAuthSDK(my_oauth_config)
global oauth_sdk # Declare as global if handle_application_tool_call uses it
oauth_sdk = ProductionMCPOAuthSDK()

Create a ProductionMCPOAuthSDK subclass and link the tool handler:
This is crucial for the SDK to know how to call your application's tools.

# your_mcp_server_main_file.py
class ProductionMCPOAuthSDK(MCPOAuthSDK):
    """
    Custom OAuth SDK subclass to link to your application's tool handler.
    """
    async def _call_application_tool(self, name: str, arguments: dict | None) -> List[types.TextContent]:
        # This method tells the SDK to call your application's specific handler
        return await handle_application_tool_call(name, arguments)

Set up OAuth protection for your tools:
This defines which tools require which scopes.

# your_mcp_server_main_file.py
def setup_oauth_protection_for_your_app():
    """
    Configures which of your application's tools are protected by OAuth scopes.
    """
    # Link the SDK to your application's tool handler
    oauth_sdk._app_call_tool_handler = handle_application_tool_call

    # Protect your tools
    oauth_sdk.protect_tool("my_protected_read_tool", scopes=["my_app:read"])
    oauth_sdk.protect_tool("my_protected_admin_tool", scopes=["my_app:admin"])

    # Tools not explicitly protected will be considered public by the SDK
    # (e.g., "my_public_tool" in this example)

    logger.info("🛡️ OAuth protection configured for your MCP server.")

Run your MCP server:

# your_mcp_server_main_file.py
async def main():
    """Main function to run your MCP server."""
    logger.info("🚀 Starting Your MCP Server with Dynamic OAuth")

    # Initialize the SDK (if not done globally)
    global oauth_sdk
    oauth_sdk = ProductionMCPOAuthSDK()

    # Register the SDK with your MCP server instance
    oauth_sdk.register_with_server(server)
    setup_oauth_protection_for_your_app() # Set up your tool protections

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        logger.info("🎉 YOUR MCP SERVER STARTED")
        await server.run(
            read_stream,
            write_stream,
            types.InitializationOptions(
                server_name="your-mcp-server-id",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())

Step 4: Run Your Server
Execute your main server file:

python your_mcp_server_main_file.py

Your MCP server will now start, with the OAuth SDK integrated and ready to protect your tools!

Usage for Your Customers (MCP Client Interaction)
Once your MCP server is running with the SDK integrated, your customers will interact with it via an MCP client (e.g., Claude Desktop). The client will see the following tools provided by the SDK:

oauth_authenticate(): Initiates the OAuth login flow. Your customer will be provided with a URL to open in their browser.

oauth_complete_manual(authorization_code="..."): For manual completion of the OAuth flow if the automatic redirect doesn't work.

oauth_check_status(): Checks the current authentication status, showing the logged-in user and their scopes.

oauth_logout(): Logs the user out and clears the authentication token.

oauth_refresh_tools(): Forces the MCP client to re-fetch the list of available tools (useful after login/logout).

After successful authentication, your customers will then be able to call the protected tools you defined (e.g., my_protected_read_tool(), my_protected_admin_tool()) based on their granted scopes.

Example: Testing with a Simple Demo MCP
To fully demonstrate and test the SDK's dynamic integration, you can create a minimal MCP server that uses the SDK. This is the another_mcp_server.py example, which serves as a blueprint for how your customers would integrate the SDK.

another_mcp_server.py (Example for your customers)

# another_mcp_server.py
import asyncio
import logging
import sys
import json
from typing import Any, Dict, List, Optional

import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Import the OAuth SDK
from mcp_oauth_sdk import MCPOAuthSDK

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("another-mcp-server")

server = Server("another-mcp-server")
oauth_sdk = None # Will be initialized later

# =============================================================================
# APPLICATION TOOLS DEFINITION (Customer's tools)
# =============================================================================

def define_application_tools():
    """Define tools for this demo MCP server."""
    return [
        types.Tool(
            name="get_greeting",
            description="Says hello to a given name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name to greet."}
                },
                "required": ["name"]
            },
        ),
        types.Tool(
            name="get_random_number",
            description="Generates a random number (requires mcp:read scope).",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="admin_action",
            description="Performs a simulated admin action (requires mcp:admin scope).",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]

# =============================================================================
# TOOL CALL HANDLER (Customer's tool logic)
# =============================================================================

async def handle_application_tool_call(name: str, arguments: dict | None) -> list[types.TextContent]:
    """Handle tool calls for this demo MCP server."""
    global oauth_sdk # Ensure oauth_sdk is accessible
    current_user = oauth_sdk.get_current_user()
    username = current_user.username if current_user else "anonymous"

    logger.info(f"Tool '{name}' called by '{username}' with arguments: {arguments}")

    if name == "get_greeting":
        greet_name = arguments.get("name", "World")
        return [types.TextContent(type="text", text=f"Hello, {greet_name}! (from {username})")]
    
    elif name == "get_random_number":
        import random
        return [types.TextContent(type="text", text=f"Your random number is: {random.randint(1, 100)} (generated by {username})")]

    elif name == "admin_action":
        return [types.TextContent(type="text", text=f"Simulated admin action performed by {username}.")]

    else:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

# =============================================================================
# ENHANCED OAUTH SDK INTEGRATION (Customer's integration point)
# =============================================================================

class ProductionMCPOAuthSDK(MCPOAuthSDK):
    """
    Enhanced OAuth SDK for this demo MCP server.
    This class links the SDK's internal tool calling mechanism to the
    application's specific tool handler (`handle_application_tool_call`).
    """
    async def _call_application_tool(self, name: str, arguments: dict | None) -> List[types.TextContent]:
        return await handle_application_tool_call(name, arguments)

# =============================================================================
# SERVER SETUP AND OAUTH PROTECTION (Customer's setup)
# =============================================================================

def setup_oauth_protection_for_demo():
    """Setup OAuth protection for demo tools."""
    global oauth_sdk # Ensure oauth_sdk is accessible
    oauth_sdk._app_call_tool_handler = handle_application_tool_call # Link SDK to app handler

    # Protect customer's tools with scopes
    oauth_sdk.protect_tool("get_random_number", scopes=["mcp:read"])
    oauth_sdk.protect_tool("admin_action", scopes=["mcp:admin"])

    logger.info("🛡️ OAuth protection configured for demo MCP server.")

# =============================================================================
# MAIN FUNCTION (Customer's main execution)
# =============================================================================

async def main():
    """Main function for the demo MCP server."""
    global oauth_sdk
    oauth_sdk = ProductionMCPOAuthSDK() # Initialize SDK, it will use environment variables

    oauth_sdk.register_with_server(server)
    setup_oauth_protection_for_demo()

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        logger.info("🎉 DEMO MCP SERVER STARTED with Dynamic OAuth")
        await server.run(
            read_stream,
            write_stream,
            types.InitializationOptions(
                server_name="demo-mcp-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())

To Test the mcp_oauth_sdk.py with this Demo:

Place mcp_oauth_sdk.py and another_mcp_server.py in the same directory.

Set the required OAuth environment variables (e.g., OAUTH_SERVER, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_SCOPES).

Run the demo server: python another_mcp_server.py

Interact with it via an MCP client, following the "Usage" section above. You'll see the SDK's OAuth tools and the demo server's tools (get_greeting, get_random_number, admin_action)