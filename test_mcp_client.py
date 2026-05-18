#!/usr/bin/env python3
"""
Simple MCP client to test kalimcp server
"""
import asyncio
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    # Server parameters - pointing to our kalimcp server
    server_params = StdioServerParameters(
        command="/home/hermes/KaliMCP/.venv/bin/kalimcp",
        args=[],
        env=None
    )
    
    print("Connecting to kalimcp server...")
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()
            print("Connected to kalimcp server")
            
            # List available tools
            tools_result = await session.list_tools()
            print("\nAvailable tools:")
            for tool in tools_result.tools:
                print(f"  - {tool.name}: {tool.description}")
            
            # Try dig_record (passive tool)
            print("\n--- Testing dig_record (passive tool) ---")
            try:
                dig_result = await session.call_tool(
                    "dig_record",
                    {"domain": "example.com", "record_type": "A"}
                )
                print("dig_record result:")
                for content in dig_result.content:
                    if hasattr(content, 'text'):
                        print(content.text)
            except Exception as e:
                print(f"Error calling dig_record: {e}")
            
            # Try an active tool (requires auth) - use the new token that includes localhost and LAN
            print("\n--- Testing nmap_scan (active tool) on localhost ---")
            try:
                # Use the token that includes 127.0.0.1 and 172.16.27.0/21
                token = "znFJ1p5tCqTKCBqWsMLw03arozBhWf41KFcVMSTMnbg"
                print(f"Using token: {token}")
                nmap_result = await session.call_tool(
                    "nmap_scan",
                    {
                        "target": "127.0.0.1",  # Scan localhost
                        "profile": "tcp-fast",
                        "authorization_token": token
                    }
                )
                print("nmap_scan result:")
                for content in nmap_result.content:
                    if hasattr(content, 'text'):
                        print(content.text)
            except Exception as e:
                print(f"Error calling nmap_scan: {e}")
                import traceback
                traceback.print_exc()
            
            # Try scanning a host on the LAN (e.g., gateway)
            print("\n--- Testing nmap_scan (active tool) on LAN gateway ---")
            try:
                # Gateway from ip addr: 172.16.27.183/21 -> network is 172.16.24.0/21
                # Let's try .1 (common gateway)
                token = "znFJ1p5tCqTKCBqWsMLw03arozBhWf41KFcVMSTMnbg"
                print(f"Using token: {token}")
                nmap_result2 = await session.call_tool(
                    "nmap_scan",
                    {
                        "target": "172.16.24.1",  # Possible gateway
                        "profile": "tcp-fast",
                        "authorization_token": token
                    }
                )
                print("nmap_scan result for 172.16.24.1:")
                for content in nmap_result2.content:
                    if hasattr(content, 'text'):
                        print(content.text)
            except Exception as e:
                print(f"Error calling nmap_scan on gateway: {e}")
                
            # Try scanning another host in the LAN - our own IP
            print("\n--- Testing nmap_scan (active tool) on self ---")
            try:
                token = "znFJ1p5tCqTKCBqWsMLw03arozBhWf41KFcVMSTMnbg"
                print(f"Using token: {token}")
                nmap_result3 = await session.call_tool(
                    "nmap_scan",
                    {
                        "target": "172.16.27.183",  # Our own IP from ip addr
                        "profile": "tcp-fast",
                        "authorization_token": token
                    }
                )
                print("nmap_scan result for 172.16.27.183:")
                for content in nmap_result3.content:
                    if hasattr(content, 'text'):
                        print(content.text)
            except Exception as e:
                print(f"Error calling nmap_scan on self: {e}")

if __name__ == "__main__":
    asyncio.run(main())