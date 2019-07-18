import io
import json
import time
import socket
import logging
import threading
import traceback
import multiprocessing
from enum import Enum
import xml.etree.ElementTree as etree

"""
MCP Packet    (double hex-encoded)

+------------------------+------------------------+-------------------------+--------------+
|   SRC MAC [6 bytes]    |   DST MAC [6 bytes]    |    PAYLOAD [...]        | CRC [1 byte] |
+------------------------+------------------------+-------------------------+--------------+


Payload

+---------------------+--------------+-----------------+---------------------+-------------------------------+--------------+
|   LENGTH [2 bytes]  |  TAG[1 byte] | TOKEN [4 bytes] |  COMMAND ID[1 byte] |   COMMAND/RESPONSE DATA [...] |  CRC[1 byte] |
+---------------------+--------------+-----------------+---------------------+-------------------------------+--------------+
"""

class MCPPacket:
	def __init__(self):
		self.SRC_MAC  = None # 6 bytes, IPHONE app sends: '\x00\x00\x00\x00\x00\x06'
		self.DST_MAC  = None # 6 bytes, the MAC address of the destination
		self.payload  = None # MCP command or reply (direction is encoded in this object)
		self.checksum = None # 1 byte, the checksum?
		
		#helper variable
		self.buffer = b'' #buffer never has the checksum in it!
	
	@staticmethod
	def construct(src_mac, dst_mac, payload):
		t = MCPPacket()
		t.SRC_MAC  = src_mac
		t.DST_MAC  = dst_mac
		t.payload  = payload
		return t
	
	def to_bytes(self):
		#updating buffer
		self.buffer = self.SRC_MAC + self.DST_MAC + self.payload.to_bytes()
		#returning the packet bytes
		return (self.buffer + MCPPacket.calc_checksum(self.buffer).to_bytes(1, byteorder = 'big', signed = False)).hex().upper().encode()
		
	@staticmethod
	def from_bytes(data, verify_checksum = True):
		"""
		Parses the input and returns the appropriate packet object
		
		data: double-hex encoded bytes, as seen on the socket
		"""
		mcpp = MCPPacket()
		
		mcpp.buffer = bytes.fromhex(data.decode())
		if verify_checksum == True:
			if mcpp.buffer[-1] != MCPPacket.calc_checksum(mcpp.buffer[:-1]):
				raise Exception('MCPPacket checksum mismatch!')
		
		mcpp.SRC_MAC = mcpp.buffer[:6]
		mcpp.DST_MAC = mcpp.buffer[6:12]
		mcpp.payload = MCP.from_bytes(mcpp.buffer[12:-1])
		mcpp.checksum = mcpp.buffer[-1]
		
		return mcpp
	
	@staticmethod
	def calc_checksum(buffer):
		"""
		Calculates the Packet's checksum
		buffer: bytearray or bytes
		"""
		cks = 0
		for c in buffer.hex().upper():
			cks += ord(c)
		
		return cks & 0xFF
		
	def __repr__(self):
		t = ''
		t += '= NetworkDatagram =\r\n'
		t += 'SRC_MAC        : %s\r\n' % self.SRC_MAC.hex().upper()
		t += 'DST_MAC        : %s\r\n' % self.DST_MAC.hex().upper()
		t += 'checksum       : %s\r\n' % hex(self.checksum).upper()
		t += repr(self.payload)
		return t		

class MCP():
	"""
	BYTE_MULTIPLIER	= 2
	ADDRESS_SIZE	= 6 * BYTE_MULTIPLIER
	LENGTH_SIZE		= 2 * BYTE_MULTIPLIER
	TAG_SIZE		= 1 * BYTE_MULTIPLIER
	TOKEN_SIZE		= 4 * BYTE_MULTIPLIER
	COMMAND_SIZE	= 1 * BYTE_MULTIPLIER
	CHECKSUM_SIZE	= 1 * BYTE_MULTIPLIER
	FRAME_SIZE		= LENGTH_SIZE + TAG_SIZE + TOKEN_SIZE + COMMAND_SIZE + CHECKSUM_SIZE
	TMCP_MIN_SIZE	= ADDRESS_SIZE * 2 + FRAME_SIZE + 2
	"""
	LENGTH_SIZE = 2
	TAG_SIZE = 1
	TOKEN_SIZE = 4
	COMMAND_SIZE = 1
	CHECKSUM_SIZE = 1
	COMMAND_POS = LENGTH_SIZE + TAG_SIZE + TOKEN_SIZE
	HEADER_SIZE = LENGTH_SIZE + TAG_SIZE + TOKEN_SIZE + COMMAND_SIZE + CHECKSUM_SIZE
	
	
	def __init__(self):
		self.buffer = None
		self.validateChecksum	= True
		self.length = None
		self.tag	= None
		self.token	= None
		self.command	= None
		self.command_id = None
		self.payload	= ''
		self.isResponse	= False
		self.checksum = None
		
	@staticmethod
	def construct(cmd, tag = 0, token = 0, isResponse = False):
		if cmd.__class__ == MCPGenericCommand:
			t = MCP()
			t.command = cmd
			t.command_id = cmd.command_id
			t.tag = tag
			t.token = token
			t.isResponse = isResponse
		
		else:
			t = MCP()
			t.command = cmd
			if isResponse:
				t.command_id = MCP2Response[cmd.__class__]
				t.command_id |= 0x80
			else:
				t.command_id = MCP2Command[cmd.__class__]
			t.tag = tag
			t.token = token
			t.isResponse = isResponse
		
		return t
		
	@staticmethod
	def from_bytes(data):
		mcp = MCP()
		mcp.buffer = data
		data = io.BytesIO(data)
		
		mcp.length = int.from_bytes(data.read(MCP.LENGTH_SIZE), byteorder = 'big', signed = False)
		mcp.tag = int.from_bytes(data.read(MCP.TAG_SIZE), byteorder = 'big', signed = False)
		mcp.token = int.from_bytes(data.read(MCP.TOKEN_SIZE), byteorder = 'big', signed = False)
		mcp.command_id = int.from_bytes(data.read(MCP.COMMAND_SIZE), byteorder = 'big', signed = False)
		
		if mcp.command_id & 0x80:
			mcp.isResponse = True
			mcp.command_id = mcp.command_id & ~0x80
			#'RESPONSE PACKET'
			
		rest = data.read()
		mcp.payload = rest[:-1]
		mcp.checksum = rest[-1]

		if mcp.checksum != MCP.calc_checksum(mcp.buffer[:-1]):
			raise Exception('Checksum mismatch!')
		
		if not mcp.isResponse:
			if mcp.command_id in Command2MCP:
				mcp.command = Command2MCP[mcp.command_id].from_bytes(mcp.payload)
			else:
				mcp.command = MCPUnknownCommand.from_bytes(mcp.payload)
		
		else:
			if mcp.command_id in Response2MCP:
				mcp.command = Response2MCP[mcp.command_id].from_bytes(mcp.payload)
			else:
				mcp.command = MCPUnknownResponse.from_bytes(mcp.payload)

		return mcp
		
	def to_bytes(self):
		self.buffer = self.tag.to_bytes(1, byteorder = 'big', signed = False)
		self.buffer += self.token.to_bytes(4, byteorder = 'big', signed = False)
		if self.isResponse:
			self.buffer += (self.command_id | 0x80 ).to_bytes(1, byteorder = 'big', signed = False) 
		else:	
			self.buffer += self.command_id.to_bytes(1, byteorder = 'big', signed = False)
		temp = self.command.to_bytes()
		if temp:
			self.buffer += temp
		
		self.length = len(self.buffer) + 3
		self.buffer = self.length.to_bytes(2, byteorder = 'big', signed = False) + self.buffer
		
		return self.buffer + self.calc_checksum(self.buffer).to_bytes(1, byteorder = 'big', signed = False)

	@staticmethod
	def calc_checksum(buffer):
		cks = int.from_bytes(buffer[:2], byteorder = 'big', signed = False)
		for byte in buffer[2:]:	
			cks += byte
			cks = cks & 0xFF
			
		return cks & 0xFF

	def __repr__(self):
		t = ''
		t += ' == MCP ==\r\n'
		t += ' isResponse: %s\r\n' % str(self.isResponse)
		t += ' Length    : %d\r\n' % self.length
		t += ' Tag       : %s\r\n' % hex(self.tag).upper()
		t += ' Token     : %s\r\n' % hex(self.token).upper()
		t += ' Command ID: %s ( %s )\r\n' % (self.command_id, MCPCommand(self.command_id).name)
		t += ' Checksum : %s\r\n' % hex(self.checksum).upper()
		t += repr(self.command)
		
		
		return t
		
class MCPUnknownResponse:
	def __init__(self):
		self.name = 'MCPUnknownResponse'
		self.payload = None
		
	@staticmethod
	def from_bytes(data):
		cmd = MCPUnknownResponse()
		cmd.payload = data
		return cmd
		
	def to_bytes(self):
		return self.payload
		
	def __repr__(self):
		t = '  === MCPUnknownResponse ===\n'
		t += '  Payload: %s\n' % self.payload
		return t
		
class MCPUnknownCommand:
	def __init__(self):
		self.name = 'MCPUnknownCommand'
		self.payload = ''
		
	@staticmethod
	def from_bytes(data):
		cmd = MCPUnknownCommand()
		cmd.payload = data
		return cmd
		
	def to_bytes(self):
		return self.payload
		
	def __repr__(self):
		t = '=== MCPUnknownCommand ===\n'
		t += 'Payload: %s\n' % self.payload
		return t
		
class MCPGenericCommand:
	def __init__(self):
		self.name = 'MCPGenericCommand'
		self.command_id = None
		self.value = None
	
	@staticmethod
	def construct( id, value = 0):
		t = MCPGenericCommand()
		t.command_id = id
		t.value = value
		return t
		
	def to_bytes(self):
		return self.value.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '=== MCPGenericCommand ===\n'
		t += 'value: %s\n' % self.value
		return t


class MCPGetMAC:
	def __init__(self):
		self.data = None

	@staticmethod
	def construct():
		return MCPGetMAC()

	@staticmethod
	def from_bytes(data):
		t = MCPGetMAC()
		t.mac_addr = data 
		return t
		
	def to_bytes(self):
		return self.data
		
	def __repr__(self):
		t = '=== MCPGetMAC ===\n'
		return t
		
class MCPGetMACResponse:
	def __init__(self):
		self.mac_addr = None

	@staticmethod
	def construct(mac_addr):
		t = MCPGetMACResponse()
		t.mac_addr = mac_addr 
		return t

	@staticmethod
	def from_bytes(data):
		t = MCPGetMACResponse()
		t.mac_addr = data 
		return t
		
	def to_bytes(self):
		return self.mac_addr
		
	def __repr__(self):
		t = '=== MCPGetMACResponse ===\n'
		t += 'MAC Address: %s\n' % self.mac_addr
		return t
		
class MCPRemoveUser:
	def __init__(self):
		self.user_id = None
	
	@staticmethod
	def construct(user_id):
		t = MCPRemoveUser()
		t.user_id = user_id
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPRemoveUser()
		t.user_id = data[0]
		return t
		
	def to_bytes(self):
		return self.user_id.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '   === MCPRemoveUser ===\n'
		t+= '   User ID: %s' % self.user_id
		return t
		
class MCPRemoveUserResponse:
	def __init__(self):
		self.user_id = None
	
	@staticmethod
	def construct(user_id):
		t = MCPRemoveUser()
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPRemoveUser()
		return t
		
	def to_bytes(self):
		return self.user_id
		
	def __repr__(self):
		t = '   === MCPRemoveUserResponse ===\n'
		return t
		
class MCPGetUserName:
	def __init__(self):
		self.user_id = None
	
	@staticmethod
	def construct(user_id):
		t = MCPGetUserName()
		t.user_id = user_id
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPGetUserName()
		t.user_id = data[0]
		return t
		
	def to_bytes(self):
		return self.user_id.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '   === MCPGetUserName ===\n'
		return t
		
class MCPGetUserNameResponse:
	def __init__(self):
		self.username = None
	
	@staticmethod
	def construct(username):
		t = MCPGetUserNameResponse()
		t.username = username
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPGetUserNameResponse()
		t.username = data.decode()
		return t
		
	def to_bytes(self):
		return self.username.encode()
		
	def __repr__(self):
		t = '   === MCPGetUserNameResponse ===\n'
		t = '   Username: %s\n' % self.username
		return t

class MCPGetUserRights:
	def __init__(self):
		self.data = 0
	
	@staticmethod
	def construct():
		return MCPGetUserRights()

	@staticmethod
	def from_bytes(data):
		t = MCPGetUserRights()
		t.data = int.from_bytes(data, byteorder = 'big', signed = False)
		return t
		
	def to_bytes(self):
		return self.data.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '   === MCPGetUserRights ===\n'
		return t

class MCPGetUserRightsResponse:
	def __init__(self):
		self.user_id = None
		self.user_rights = []
	
	@staticmethod
	def construct(user_id, user_rights):
		t = MCPGetUserRightsResponse()
		t.user_id = user_id
		t.user_rights = user_rights
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPGetUserRightsResponse()
		t.user_id = data[0]
		tt = []
		for r in data[1:]:
			tt.append(r)
		t.user_rights = tt
		return t
		
	def to_bytes(self):
		t =  self.user_id.to_bytes(1, byteorder = 'big', signed = False)
		for r in self.user_rights:
			t += r.to_bytes(1, byteorder = 'big', signed = False)
		return t
		
	def __repr__(self):
		t = '   === MCPGetUserRightsResponse ===\n'
		t += '   user_id: %s\n' % self.user_id
		t += '   user_rights: %s\n' % self.user_rights
		return t

class MCPSetUserRights:
	def __init__(self):
		self.user_id = None
		self.user_rights = []
	
	@staticmethod
	def construct(user_id, user_rights):
		t = MCPSetUserRights()
		t.user_id = user_id
		t.user_rights = user_rights
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPSetUserRights()
		t.user_id = data[0]
		tt = []
		for r in data[1:]:
			tt.append(r)
		t.user_rights = tt
		return t
		
	def to_bytes(self):
		t =  self.user_id.to_bytes(1, byteorder = 'big', signed = False)
		for r in self.user_rights:
			t += r.to_bytes(1, byteorder = 'big', signed = False)
		return t
		
	def __repr__(self):
		t = '   === MCPSetUserRights ===\n'
		t += '   user_id: %s\n' % self.user_id
		t += '   user_rights: %s\n' % self.user_rights
		return t		
	
class MCPGetValue:
	def __init__(self):
		self.value_id = None
	
	@staticmethod
	def construct(value_id):
		t = MCPGetValue()
		t.value_id = value_id
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPGetValue()
		t.value_id = int.from_bytes(data, byteorder = 'big', signed = False)
		return t
		
	def to_bytes(self):
		return self.value_id.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '=== MCPGetValue ===\n'
		t += 'Value ID: %s\n' % self.value_id
		return t
		
class MCPSetValue:
	def __init__(self):
		self.value_id = None
		self.value = None
	
	@staticmethod
	def construct(value_id, value):
		t = MCPSetValue()
		t.value_id = value_id
		t.value = value
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPSetValue()
		t.value_id = int.from_bytes(data[0], byteorder = 'big', signed = False)
		t.value = int.from_bytes(data[1], byteorder = 'big', signed = False)
		return t
		
	def to_bytes(self):
		return self.value_id.to_bytes(1, byteorder = 'big', signed = False) + self.value.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '=== MCPSetValue ===\n'
		t += 'Value ID: %s\n' % self.value_id
		t += 'Value   : %s\n' % self.value
		return t

class MCPErrorResponse:
	def __init__(self):
		self.error_code = None
		
	@staticmethod
	def construct(error_code):
		t = MCPErrorResponse()
		t.error_code = error_code
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPErrorResponse()
		t.error_code = MCPError(data[0])
		return t
		
	def to_bytes(self):
		return self.error_code.value.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '   === MCPErrorResponse ===\n'
		t += '   Code   : %s\n' % self.error_code.value
		t += '   Name   : %s\n' % self.error_code.name
		return t
		
class MCPLoginResponse:
	def __init__(self):
		self.auth_tag = None
		self.auth_token = None
		
	@staticmethod
	def construct(auth_tag, auth_token):
		t = MCPLoginResponse()
		t.auth_tag = auth_tag
		t.auth_token = auth_token
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPLoginResponse()
		t.auth_tag = data[0]
		t.auth_token = int.from_bytes(data[1:], byteorder = 'big', signed = False)
		return t
		
	def to_bytes(self):
		t = self.auth_tag.to_bytes(1, byteorder = 'big', signed = False)
		return t + self.auth_token.to_bytes(4, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '   === MCPLoginResponse ===\n'
		t += '   Tag   : %s\n' % self.auth_tag
		t += '   Token : %s\n' % self.auth_token
		return t
	
class MCPLogin:
	def __init__(self):
		self.username = None
		self.password = None
		
	@staticmethod
	def construct(username, password):
		t = MCPLogin()
		t.username = username
		t.password = password
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPLogin()
		username_length = data[0]
		t.username = data[1:1+username_length].decode()
		t.password = data[1+username_length:].decode()
		return t
		
	def to_bytes(self):
		return len(self.username).to_bytes(1, byteorder = 'big', signed = False) + self.username.encode() + self.password.encode()
		
	def __repr__(self):
		t = '   === MCPLogin ===\n'
		t += '   Username : %s\n' % self.username
		t += '   Password : %s\n' % self.password
		return t
		
class MCPAddUser:
	def __init__(self, owerflow = None):
		self.username = None
		self.password = None
		self.owerflow = owerflow #specifies the size of the username (one byte max!), if not matching the username then things go south...
		
	@staticmethod
	def construct(username, password, owerflow):
		t = MCPAddUser()
		t.owerflow = owerflow
		t.username = username
		t.password = password
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPAddUser()
		username_length = data[0]
		t.username = data[1:1+username_length].decode()
		t.password = data[1+username_length:].decode()
		return t
		
	def to_bytes(self):
		if self.owerflow:
			return self.owerflow + self.username.encode() + self.password.encode()
		else:
			return len(self.username).to_bytes(1, byteorder = 'big', signed = False) + self.username.encode() + self.password.encode()
		
	
	def __repr__(self):
		t = '   === MCPAddUser ===\n'
		t += '   Username : %s\n' % self.username
		t += '   Password : %s\n' % self.password
		return t
		
class MCPChangePasswordOfUser:
	def __init__(self):
		self.user_id = None
		self.password = None
		
	@staticmethod
	def construct(user_id, password):
		t = MCPChangePasswordOfUser()
		t.user_id = user_id
		t.password = password
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPChangePasswordOfUser()
		t.user_id = data[0]
		t.password = data[1+username_length:].decode()
		return t
		
	def to_bytes(self):
		return self.user_id.to_bytes(1, byteorder = 'big', signed = False) + self.password.encode()
		
	def __repr__(self):
		t = '   === MCPChangePasswordOfUser ===\n'
		t += '   User ID : %s\n' % self.user_id
		t += '   Password : %s\n' % self.password
		return t
		
		
class MCPChangePassword:
	def __init__(self):
		self.password = None
		
	@staticmethod
	def construct(password):
		t = MCPChangePassword()
		t.password = password
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPChangePassword()
		t.password = data.decode()
		return t
		
	def to_bytes(self):
		return self.password.encode()
		
	def __repr__(self):
		t = '   === MCPChangePassword ===\n'
		t += '   Password : %s\n' % self.password
		return t
		
class MCPSetName:
	def __init__(self):
		self.name = None
		
	@staticmethod
	def construct(name):
		t = MCPSetName()
		t.name = name
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPSetName()
		t.name = data.decode()
		return t
		
	def to_bytes(self):
		return self.name.encode()
		
	def __repr__(self):
		t = '   === MCPSetName ===\n'
		t += '   name : %s\n' % self.name
		return t
		
class MCPGetWifiState:
	def __init__(self):
		self.data = 0
	
	@staticmethod
	def construct():
		return MCPGetWifiState()

	@staticmethod
	def from_bytes(data):
		t = MCPGetWifiState()
		t.data = data[0]
		return t
		
	def to_bytes(self):
		return self.data.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '=== MCPGetWifiState ===\n'
		return t
		
class MCPScanWifi:
	def __init__(self):
		self.data = None
	
	@staticmethod
	def construct():
		return MCPScanWifi()

	@staticmethod
	def from_bytes(data):
		t = MCPScanWifi()
		return t
		
	def to_bytes(self):
		return self.data
		
	def __repr__(self):
		t = '=== MCPScanWifi ===\n'
		return t
		
class MCPWifiFound:
	def __init__(self):
		self.data = None
	
	@staticmethod
	def construct(data):
		t = MCPWifiFound()
		t.data = data
		return t

	@staticmethod
	def from_bytes(data):
		t = MCPWifiFound()
		t.data = data.decode()
		return t
		
	def to_bytes(self):
		return self.data.encode()
		
	def __repr__(self):
		t = '   === MCPWifiFound ===\n'
		t+= '   Wifi: %s\n' % self.data
		return t
		
class MCPGetUserIds:
	def __init__(self):
		self.data = None
	
	@staticmethod
	def construct():
		return MCPGetUserIds()

	@staticmethod
	def from_bytes(data):
		t = MCPGetUserIds()
		return t
		
	def to_bytes(self):
		return self.data
		
	def __repr__(self):
		t = '=== MCPGetUserIds ===\n'
		return t
		
class MCPGetUserIdsResponse:
	def __init__(self):
		self.user_ids = []
	
	@staticmethod
	def construct(user_ids):
		t = MCPGetUserIdsResponse()
		t.user_ids = user_ids
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPGetUserIdsResponse()
		tt = []
		for r in data:
			tt.append(r)
		t.user_ids = tt
		return t
		
	def to_bytes(self):
		t = b''
		for r in self.user_rights:
			t += r.to_bytes(1, byteorder = 'big', signed = False)
		return t
		
	def __repr__(self):
		t = '   === MCPGetUserIdsResponse ===\n'
		t += '   user_ids: %s\n' % self.user_ids
		return t
		
class MCPGetName:
	def __init__(self):
		self.data = None
	
	@staticmethod
	def construct():
		return MCPGetName()

	@staticmethod
	def from_bytes(data):
		t = MCPGetName()
		return t
		
	def to_bytes(self):
		return self.data
		
	def __repr__(self):
		t = '=== MCPGetName ===\n'
		return t
		
class MCPGetNameResponse:
	def __init__(self):
		self.device_name = None
	
	@staticmethod
	def construct(device_name):
		t =  MCPGetNameResponse()
		t.device_name = device_name
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPGetNameResponse()
		t.device_name = data.decode()
		return t
		
	def to_bytes(self):
		return self.device_name.encode()
		
	def __repr__(self):
		t = '   === MCPGetNameResponse ===\n'
		t+= '   Device Name: %s\n' % self.device_name
		return t
		
class MCPGETGWVersion:
	def __init__(self):
		self.data = 0
	
	@staticmethod
	def construct():
		return MCPGETGWVersion()

	@staticmethod
	def from_bytes(data):
		t = MCPGETGWVersion()
		return t
		
	def to_bytes(self):
		return self.data.to_bytes(1, byteorder = 'big', signed = False)
		
	def __repr__(self):
		t = '=== MCPGETGWVersion ===\n'
		return t
		
class MCPGETGWVersionResponse:
	def __init__(self):
		self.gw_version = None
	
	@staticmethod
	def construct(gw_version):
		t = MCPGETGWVersionResponse()
		t.gw_version = gw_version
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPGETGWVersionResponse()
		t.gw_version = data.decode()
		return t
		
	def to_bytes(self):
		return self.gw_version.encode()
		
	def __repr__(self):
		t = '   === MCPGETGWVersionResponse ===\n'
		t+= '   GW version: %s\n' % self.gw_version
		return t
		
class MCPDebug:
	def __init__(self, data):
		"""
		needs to be bytes!
		"""
		self.data = data
		
	@staticmethod
	def construct(data):
		return MCPDebug(data)

	@staticmethod
	def from_bytes(data):
		t = MCPDebug(data)
		return t
		
	def to_bytes(self):
		return self.data
		
	def __repr__(self):
		t = '   === MCPDebug ===\n'
		return t
		
class MCPPing:
	def __init__(self):
		self.data = ''
		
	@staticmethod
	def construct(data = 'ping'):
		t = MCPPing()
		t.data = data
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPPing()
		t.data = data
		return t
		
	def to_bytes(self):
		return self.data.encode()
		
	def __repr__(self):
		t = '   === MCPPing ===\n'
		t += '   data: %s\n' % self.data
		return t
		
class MCPPingResponse:
	def __init__(self):
		self.data = ''
		
	@staticmethod
	def construct(data = 'ping'):
		t = MCPPingResponse()
		t.data = data
		return t
		
	@staticmethod
	def from_bytes(data):
		t = MCPPingResponse()
		t.data = data
		return t
		
	def to_bytes(self):
		return self.data.encode()
		
	def __repr__(self):
		t = '   === MCPPingResponse ===\n'
		t += '   data: %s\n' % self.data
		return t


class MCPLogout:
	def __init__(self):
		self.data = None
		
	@staticmethod
	def construct():
		return MCPLogout()

	@staticmethod
	def from_bytes(data):
		t = MCPLogout()
		return t
		
	def to_bytes(self):
		return self.data
		
	def __repr__(self):
		t = '   === MCPLogout ===\n'
		return t
		
class JCMP:
	def __init__(self):
		self.cmd = None
		
	@staticmethod
	def construct(cmd):
		t = JCMP()
		t.cmd = cmd
		return t

	@staticmethod
	def from_bytes(data):
		t = JCMP()
		t.cmd = json.loads(data.decode())
		return t
		
	def to_bytes(self):
		return json.dumps(self.cmd, separators=(',', ':')).encode()
		
	def __repr__(self):
		t = '   === JCMP ===\n   '
		t += json.dumps(self.cmd, indent=4, sort_keys=True).replace('\n','\n   ')
		return t
		
class JCMPResponse:
	def __init__(self):
		self.response = None
		
	@staticmethod
	def construct(response):
		t = JCMPResponse()
		t.response = response
		return t

	@staticmethod
	def from_bytes(data):
		t = JCMPResponse()
		t.response = json.loads(data)
		return t
		
	def to_bytes(self):
		return json.dumps(self.response, separators=(',', ':')).encode() #separators to skip whitespaces
		
	def __repr__(self):
		t = '   === JCMPResponse ===\n   '
		t += json.dumps(self.response, indent=4, sort_keys=True).replace('\n','\n   ')
		return t
	
		
class JCMPCommand(Enum):
	JMCP_GET_VALUES   = "{\"cmd\":\"GET_VALUES\"}"
	JMCP_GET_GROUPS   = "{\"cmd\":\"GET_GROUPS\"}"
	JMCP_GET_USERS    = "{\"cmd\":\"GET_USERS\"}"
	JMCP_KEY_FOR_USER = "forUser"

class MCPCommand(Enum):
	PING              = 0
	ERROR             = 1
	GET_MAC           = 2
	SET_VALUE         = 3
	GET_VALUE         = 4
	DEBUG             = 5
	JMCP              = 6
	GET_GW_VERSION    = 7
	
	LOGIN             = 16
	LOGOUT            = 17
	
	GET_USER_IDS      = 32
	GET_USER_NAME     = 33
	ADD_USER          = 34
	CHANGE_PASSWD     = 35
	REMOVE_USER       = 36
	SET_USER_RIGHTS   = 37
	GET_NAME          = 38
	SET_NAME          = 39
	GET_USER_RIGHTS   = 40
	ADD_PORT          = 41
	ADD_GROUP         = 42
	REMOVE_GROUP      = 43
	SET_GROUP_NAME    = 44
	GET_GROUP_NAME    = 45
	SET_GROUPED_PORTS = 46
	GET_GROUPED_PORTS = 47
	GET_PORTS         = 48
	GET_TYPE          = 49
	GET_STATE         = 50
	SET_STATE         = 51
	GET_PORT_NAME     = 52
	SET_PORT_NAME     = 53
	SET_TYPE          = 54
	
	GET_GROUP_IDS     = 64
	INHERIT_PORT      = 65
	REMOVE_PORT       = 66
	
	SET_SSL           = 80
	SCAN_WIFI         = 81
	WIFI_FOUND        = 82
	GET_WIFI_STATE    = 83
	HM_GET_TRANSITION = 112
	
	
	CHANGE_USER_NAME  = 67
	CHANGE_USER_NAME_OF_USER  = 68
	CHANGE_PASSWORD_OF_USER   = 69
	
MCP2Command = {
	MCPPing: 0,
	
	MCPGetMAC : 2,
	MCPSetValue : 3, #login needed
	MCPGetValue : 4, #login needed
	MCPDebug:5,
	JCMP : 6,
	MCPGETGWVersion: 7, #no login needed!!!
	
	MCPLogin : 16,
	MCPLogout : 17,
	
	MCPGetUserIds: 32, #login needed
	MCPGetUserName: 33, #login needed
	MCPAddUser : 34, #no login needed!!!
	MCPChangePassword: 35,
	MCPRemoveUser: 36,
	
	MCPSetUserRights: 37,  #login needed
	MCPGetName:38, #no login needed!!!
	MCPSetName:39,  #login needed
	MCPGetUserRights:40, #login needed
	
	MCPChangePasswordOfUser:69, #command not found :(
	
	MCPScanWifi:81,
	MCPWifiFound:82,
	MCPGetWifiState:83
}

MCP2Response = {
	MCPPingResponse : 0,
	MCPErrorResponse : 1,
	MCPGetMACResponse : 2,
	
	JCMPResponse: 6,
	
	MCPGetUserIdsResponse: 32,
	MCPGetUserNameResponse: 33,
	MCPRemoveUserResponse: 36,
	MCPGetNameResponse:38,
	#MCPGetValueResponse : 4,
	#MCPSetValueResponse : 3,
	#
	#MCPDebugResponse:5,
	#JCMPResponse : 6,
	#MCPGETGWVersionResponse: 7,
	MCPLoginResponse : 16,
	#MCPLogoutResponse : 17,
	#MCPAddUserResponse : 34,
	#MCPChangePasswordResponse: 35,
	#
	#MCPSetNameResponse:39,
	MCPGetUserRightsResponse:40,
	#
	#MCPChangePasswordOfUserResponse:69,
	#
	#MCPScanWifiResponse:81,
	#MCPWifiFoundResponse:82,
	#MCPGetWifiStateResponse:83
}
	
Command2MCP = {
	0 : MCPPing,
	1 : MCPErrorResponse,
	2 : MCPGetMAC,
	3 : MCPSetValue,
	4 : MCPGetValue,
	5 : MCPDebug,
	6 : JCMP,
	7 : MCPGETGWVersion,
	
	
	16: MCPLogin,
	17: MCPLogout,
	
	32: MCPGetUserIds,
	33: MCPGetUserName,
	34: MCPAddUser,
	35: MCPChangePassword,
	36: MCPRemoveUser,
	37: MCPSetUserRights,
	38: MCPGetName,
	39: MCPSetName,
	40: MCPGetUserRights,
	
	69: MCPChangePasswordOfUser,
	
	81: MCPScanWifi,
	82: MCPWifiFound,
	83: MCPGetWifiState,
	
	666:MCPUnknownCommand
}

Response2MCP = {
	0 : MCPPingResponse,
	1 : MCPErrorResponse,
	2 : MCPGetMACResponse,
	
	6 : JCMPResponse,
	7 : MCPGETGWVersionResponse,
	
	16: MCPLoginResponse,
	
	32: MCPGetUserIdsResponse,
	33: MCPGetUserNameResponse,
	36: MCPRemoveUserResponse,

	#4 : MCPGetValueResponse,
	#3 : MCPSetValueResponse,
	#"{\"cmd\":\"GET_VALUES\"}" : MCPJMCPGetValuesResponse,
	38: MCPGetNameResponse,
	40: MCPGetUserRightsResponse,
	
	#17: MCPLogoutResponse,
	
	666:MCPUnknownResponse

}

class MCPError(Enum):
	COMMAND_NOT_FOUND   = 0
	INVALID_PROTOCOL    = 1
	LOGIN_FAILED        = 2
	INVALID_TOKEN       = 3
	USER_ALREADY_EXISTS = 4
	NO_EMPTY_USER_SLOT  = 5
	INVALID_PASSWORD    = 6
	INVALID_USERNAME    = 7
	USER_NOT_FOUND      = 8
	PORT_NOT_FOUND      = 9
	PORT_ERROR          = 10
	GATEWAY_BUSY        = 11
	PERMISSION_DENIED   = 12
	NO_EMPTY_GROUP_SLOT = 13
	GROUP_NOT_FOUND     = 14
	INVALID_PAYLOAD     = 15
	OUT_OF_RANGE        = 16
	ADD_PORT_ERROR      = 17
	NO_EMPTY_PORT_SLOT  = 18
	ADAPTER_BUSY        = 19
	
class MCPDeviceAttrs:
	def __init__(self):
		self.swVersion = None
		self.hwVersion = None
		self.mac = None
		self.protocol = None
		
	@staticmethod
	def construct(mac, sw_version = '2.5.0', hw_version = '1.0.0', protocol = 'MCP V3.0'):
		t = MCPDeviceAttrs()
		t.swVersion = sw_version
		t.hwVersion = hw_version
		t.mac = mac
		t.protocol = protocol
		return t
		
	@staticmethod
	def from_xml(xml_data):
		tree = etree.fromstring(xml_data)
		data = tree.attrib
	
		t = MCPDeviceAttrs()
		t.swVersion = data.get('swVersion')
		t.hwVersion = data.get('hwVersion')
		t.mac = b''.join([bytes.fromhex(x) for x in data.get('mac').split(':')])
		t.protocol = data.get('protocol')
		return t
		
	def to_xml(self):
		root = etree.Element('LogicBox')
		data = self.to_dict()
		for key in data:
			root.attrib[key] = data[key]
		return etree.tostring(root).decode()
		
	def to_dict(self):
		t = {}
		t['swVersion'] = self.swVersion
		t['hwVersion'] = self.hwVersion
		t['mac'] = ':'.join(format(b,'02x') for b in self.mac)
		t['protocol'] = self.protocol
		return t
		
	def __str__(self):
		return str(self.to_dict())
	
		
class MCPDiscover:
	def __init__(self, listen_ip = '', broadcast_ip = '255.255.255.255'):
		self.listen_ip = listen_ip
		self.broadcast_ip = broadcast_ip
		self.listen_port = 4002
		self.broadcast_port = 4001
		self.broadcast_amount = 4
		
		self.broadcast_wait_time = 2
		
		self.devices = {}
		
		self.close_evt = threading.Event()
		
		root = etree.Element('Discover')
		root.attrib['target'] = 'LogicBox'
		self.broadcast_data = etree.tostring(root)
		
		
	def send_broadcast(self):
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cs:
			try:
				cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
				for i in range(self.broadcast_amount):
					cs.sendto(self.broadcast_data, (self.broadcast_ip, self.broadcast_port))
					time.sleep(self.broadcast_wait_time)
			except Exception as e:
				logging.exception('MCPDiscover broadcast socket exception!')
			

		
	def listener(self):
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cs:
			try:
				cs.settimeout(1)
				cs.bind((self.listen_ip, self.listen_port))
				while not self.close_evt.set():
					try:
						data, addr = cs.recvfrom(65535)
					except socket.timeout:
						continue
						
					try:
							logging.debug("received message: %s" % data)
							dev = MCPDeviceAttrs.from_xml(data.decode())
							self.devices[addr[0]] = dev
					except:
						pass
					
			except Exception as e:
				logging.exception('MCPDiscover listening socket exception!')
		
	def run(self):
		lt = threading.Thread(target=self.listener)
		lt.daemon = True
		lt.start()
		
		self.send_broadcast()
		self.close_evt.set()
		
		if self.devices != {}:
			logging.debug('Found %d devices!' % (len(self.devices)))
		else:
			logging.debug('Not devices found!')
		
		return
		
class MCPDiscoverResponder(multiprocessing.Process):
	def __init__(self, device_atts):
		multiprocessing.Process.__init__(self)
		self.broadcast_port = 4001
		self.device_atts = device_atts
	
		
	def run(self):
		logging.debug('MCPDiscoverResponder started!')
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cs:
			try:
				cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
				cs.bind(('', self.broadcast_port))
				while True:
					try:
						data, addr = cs.recvfrom(65535)
						logging.debug("received message from %s data: %s" % (addr[0], data))
						tree = etree.fromstring(data.decode())
						target = tree.attrib.get('target')
						if target == 'LogicBox':
							with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as soc:
								soc.sendto(self.device_atts.to_xml().encode(), (addr[0],4002))
					except Exception as e:
						traceback.print_exc()
						logging.error('MCPDiscoverResponder data handling exception! Data: %s' % str(e))
						pass
							
					
			except Exception as e:
				logging.exception('MCPDiscoverResponder exception!')	
		
	