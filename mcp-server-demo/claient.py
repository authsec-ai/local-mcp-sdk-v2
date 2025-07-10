from fastmcp import Client
from fastmcp.client.transports import SSETransport

transport = SSETransport(
    url="https://436d6ae54f10.ngrok-free.app/mcp",
)
client = Client(transport)


async def breh():
    async with client:
        # Basic server interaction
        await client.ping()
        
        # List available operations
        tools = await client.list_tools()
        resources = await client.list_resources()
        prompts = await client.list_prompts()

        #print the output
        print("Tools:", tools)
        print("Resources:", resources)
        print("Prompts:", prompts)

        # Execute operations


if __name__ == "__main__":
    import asyncio
    asyncio.run(breh())