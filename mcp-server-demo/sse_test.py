from fastmcp import FastMCP
from typing import Literal, Union
from fastapi import FastAPI
import uvicorn
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

# Initialize the FastMCP server with proper metadata
mcp_server = FastMCP(
    name="calculator-server",
    version="1.0.0",
    instructions="Provides basic arithmetic operations like addition, subtraction, multiplication, and division.",
)


custom_middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["mcp-session-id"]
    )
]
# Define the 'add' tool.
# FastMCP uses Python type hints (e.g., float, int) to automatically generate
# the tool's input schema, eliminating the need for explicit schema definitions like Zod.
@mcp_server.tool()
def add(a: float, b: float) -> float:
    """
    Adds two numbers.
    :param a: The first number.
    :param b: The second number.
    :return: The sum of a and b.
    """
    return a + b

# Define the 'calculate' tool with better return type handling
@mcp_server.tool()
def calculate(operation: Literal["add", "subtract", "multiply", "divide"], a: float, b: float) -> dict:
    """
    Performs a calculation based on the specified operation.
    :param operation: The type of operation to perform ("add", "subtract", "multiply", "divide").
    :param a: The first number.
    :param b: The second number.
    :return: The result of the operation or an error message.
    """
    if operation == "add":
        result = a + b
    elif operation == "subtract":
        result = a - b
    elif operation == "multiply":
        result = a * b
    elif operation == "divide":
        if b == 0:
            return {"error": "Cannot divide by zero"}
        result = a / b
    else:
        return {"error": "Invalid operation"}

    return {"result": str(result)}

# The original JavaScript code used a 'fetch' handler to route requests
# to /sse or /mcp paths. In Python, we can achieve similar routing by
# mounting the FastMCP server's ASGI applications onto a FastAPI instance.

        # Execute operations

http_app=mcp_server.run(transport="http",middleware=custom_middleware)

# Add this to actually start the server when running the file directly
if __name__ == "__main__":
    uvicorn.run(http_app, host="0.0.0.0", port=8000)