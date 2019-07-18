import asyncio
import ssl
import logging

from pysecur3.MCP import *

class MCPNetcommand:
	"""
	object that stores all info necessary for the communication
	"""
	def __init__(self, cmd, reader, writer):
		self.cmd = cmd
		self.reader = reader
		self.writer = writer
				

class MCPDevice:
	"""
	This class emulates a Gateway device
	"""
	def __init__(self, mac_addr, ssl_cert, ssl_key, ca_cert, discoverable = True, name = 'alma_test'):
		self.mac_addr = mac_addr
		self.device_name = name
		
		self.discoverable = discoverable
		self.ssl_cert = ssl_cert
		self.ssl_key = ssl_key
		self.ca_cert = ca_cert
		
		self.server_addr = 'sslbiseclan.itbcloud.de'
		self.server_port = 443
		self.server_connection_retry_timeout = 5
		
		self.listen_iface = ''
		self.listen_port = 4000
		
		self.reader = None
		self.writer = None
		
		self.tag = 0
		self.token = 0
		
		self.device_attr = MCPDeviceAttrs.construct(self.mac_addr)
		
		self.cmdQueue = asyncio.Queue()
		
	
	def discover_handler(self):
		"""
		Spawns a sepparate process to make this virtual device discoverable on the LAN.
		"""
		disc = MCPDiscoverResponder(self.device_attr)
		disc.daemon = True
		disc.start()
		return
		
	async def handle_server(self):
		"""
		Connects to the server and recieves the commands sent by it
		Note: You will need the appropriate certificate/key to connect to the server!
		"""
		while True:
			try:
				logging.debug('Connecting to server!')
				sslctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_cert)
				sslctx.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
				sslctx.check_hostname = False
				sslctx.verify_mode = ssl.CERT_NONE
				
				reader, writer = await asyncio.open_connection(self.server_addr, self.server_port, ssl=sslctx)
				logging.debug('Connected to server!')
			except Exception as e:
				logging.exception('Failed to connect to the server!')
				time.sleep(self.server_connection_retry_timeout)
				continue
				
			while True:
				try:
					await self.read_command(reader, writer)
				except Exception as e:
					logging.exception('MCPDevice Server communication error!')
					break
				
	async def handle_lan(self):
		"""
		Opens the port on the computer and listens for MCP commands
		"""
		loop = asyncio.get_event_loop()
		coro = asyncio.start_server(self.handle_client, self.listen_iface, self.listen_port)
		loop.create_task(coro)
		
	async def handle_client(self, reader, writer):
		"""
		This function is called when client connects to the LAN port. Constantly waits for MCP commands
		"""
		while True:
			try:
				await self.read_command(reader, writer)
			except Exception as e:
				logging.exception('Error while recieveing commands from client on %s' % writer.get_extra_info('peername'))
				break
	
	
	def construct_packet(self, response, netcmd):
		"""
		Constructs the appropriate MCP response packet, and serializes it
		"""
		payload = MCP.construct(response, tag = netcmd.cmd.payload.tag, token = self.token, isResponse = True)		
		packet = MCPPacket.construct(self.mac_addr, netcmd.cmd.SRC_MAC, payload)
		return packet.to_bytes()
		
	def handle_client_conn(self, reader, writer):
		loop = asyncio.get_event_loop()
		loop.create_task(self.handle_client(reader, writer))
		
	async def read_command(self, reader, writer):
		"""
		Reads the stream for one MCP command, automatically sends the recieved command to the main event loop.
		"""
		buff = await reader.readexactly(28)
		total_len = int.from_bytes(bytes.fromhex(buff[:28].decode())[12:14], byteorder = 'big', signed = False)
		total_len = (total_len * 2) + 13*2 # because it's hex encoded on the wire + 1 byte CRC + 2 times MAC addr hex encoded
		
		buff += await reader.readexactly(total_len - len(buff))
		
		logging.debug('Data recieved: %s' % buff)
		response_packet = MCPPacket.from_bytes(buff)
		logging.debug('Command: %s' % repr(response_packet))
		
		await self.cmdQueue.put(MCPNetcommand(response_packet, reader, writer))
		
	async def send_response(self, netcmd, response):
		"""
		Sends the response to the client.
		"""
		data = self.construct_packet(response, netcmd)
		logging.debug('Reconstructed reply: %s\n' % repr(MCPPacket.from_bytes(data)))
		logging.debug('Sending data')
		netcmd.writer.write(data)
		await netcmd.writer.drain()
		logging.debug('Data sent!')
		
	async def handle_cmd(self):
		"""
		Main event loop. Waits for commands recieved either from the server or via LAN, and processes it.
		Feel free to extend the elif part with commands you wish to have implemented.
		
		"""
		while True:
			netcmd = await self.cmdQueue.get()
			cmd_name = MCPCommand(netcmd.cmd.payload.command_id)
			#cmd in, dispatching
			
			if cmd_name == MCPCommand.GET_MAC:
				await self.get_mac(netcmd)
				
			elif cmd_name == MCPCommand.GET_NAME:
				await self.get_name(netcmd)
				
			elif cmd_name == MCPCommand.LOGIN:
				await self.login(netcmd)
				
			elif cmd_name == MCPCommand.JMCP:
				await self.jmcp(netcmd)
				
			elif cmd_name == MCPCommand.GET_USER_RIGHTS:
				await self.get_user_rights(netcmd)
			else:
				logging.debug('Unknown command!')
				await self.send_error(netcmd)
		
	def check_cert(self):
		cert_dict = ssl._ssl._test_decode_cert(self.ssl_cert)
		for i in cert_dict['subject']:
			if len(i) > 0:
				if i[0][0] == 'commonName':
					mac = bytes.fromhex(i[0][1])
		
		print('Certificate signed MAC: %s' % mac.hex())
		if mac != self.mac_addr:
			input('WARNING! MAC address in certificate doesnt match the device MAC addr! Cert: %s Device: %s' % (mac.hex(), self.mac_addr.hex()))
		
	async def run(self):
		"""
		Entry point
		"""
		self.check_cert()
		if self.discoverable == True:
			self.discover_handler()
		
		loop = asyncio.get_event_loop()
		loop.create_task(self.handle_server())
		loop.create_task(self.handle_cmd())
		loop.create_task(self.handle_lan())
			
				
	async def send_error(self, netcmd, error_code = None):
		"""
		Creates an error message and sens it to the client.
		error_code should be of MCPError type or None
		"""
		if not error_code:
			response = MCPErrorResponse.construct(MCPError.COMMAND_NOT_FOUND)
		else:
			response = MCPErrorResponse.construct(error_code)
			
		await self.send_response(netcmd, response)
	
	############################################################################
	##### Below is the actual logic for each incoming command
	##### Add new features by defining an async function below, then add it to the handle_cmd function!
	############################################################################
	
	async def get_mac(self, netcmd):
		logging.debug('get_mac')
		response = MCPGetMACResponse.construct(self.mac_addr)
		await self.send_response(netcmd, response)
		
	async def get_name(self, netcmd):
		logging.debug('get_name')
		response = MCPGetNameResponse.construct(self.device_name)
		await self.send_response(netcmd, response)
	
	async def get_user_rights(self, netcmd):
		logging.debug('get_user_rights')
		response = MCPGetUserRightsResponse.construct(netcmd.cmd.payload.command.data, [])
		await self.send_response(netcmd, response)	
		
	async def login(self, netcmd):
		logging.debug('login')
		token = 121414
		tag = 0
		response = MCPLoginResponse.construct(tag, token) #this response must go out with tag=0 token=0!!! then change it!
		await self.send_response(netcmd, response)
		self.tag = tag
		self.token = token
		
	async def jmcp(self, netcmd):
		logging.debug('jmcp')
		if 'cmd' in netcmd.cmd.payload.command.cmd:
			jcmp_cmd = netcmd.cmd.payload.command.cmd['cmd']
			t = None
			if jcmp_cmd == 'GET_USERS':
				t = [
					{
						'id': 0,
						'name': 'admin',
						'isAdmin': True,
						'groups': [],
					},
					{
						'id': 1,
						'name': 'notadmin',
						'isAdmin': False,
						'groups': [],
					},
				]
			elif jcmp_cmd == 'GET_GROUPS':
				t = []
				
			else:
				#not impelemented yet
				await self.send_error(netcmd)
				return
				
			response = JCMPResponse.construct(t)
			await self.send_response(netcmd, response)
				
