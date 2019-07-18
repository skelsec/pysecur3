from MCP import *

src_mac = bytes.fromhex('5410EC762D04')
dst_mac = b'\x54\x10\xec\x76\x2d\x03'
tag = 0
token = 0

response = MCPGetName().construct()
payload = MCP.construct(response, tag = tag, token = token, isResponse = False)		
packet = MCPPacket.construct(src_mac, dst_mac, payload)

print(packet.to_bytes().decode())