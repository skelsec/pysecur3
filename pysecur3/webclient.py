import socket
import logging

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from pysecur3.MCP import *

class MCPWebClient:
	"""
	Performs the same tasks as you do from a mobile client
	You will need to obtain a deviceid and a password for your device via https://www.bisecur-home.com/
	
	"""
	def __init__(self, device_id, password, gateway_mac, proxies = None, ssl_cert_verify = False):
		self.device_id = device_id
		self.password = password
		self.src_mac = bytes.fromhex(device_id)
		self.dst_mac = gateway_mac
		
		
		self.url = 'https://sslbisecapp.itbcloud.de/m2mcloud/'
		
		# session info thats used for authentication
		self.tag = 0
		self.token = 0
		
		self.headers = {
			'User-Agent': 'Bisecur',
			'x-flash-version': '29,0,0,113',
			'Cache-Control': 'no-cache',
			'Referer': 'app:/Bisecur.swf',
			#'Content-Type': 'application/x-www-form-urlencoded',
			'ACCEPT': 'text/plain',
			'Connection': 'close',
		}
		
		self.proxies = proxies
		self.verify = ssl_cert_verify

		
	def load_login(self, token, tag = 0):
		self.tag = tag
		self.token = token
		
	def construct_packet(self, cmd):
		payload = MCP.construct(cmd, tag = self.tag, token = self.token)		
		packet = MCPPacket.construct(self.src_mac, self.dst_mac, payload)
		return packet.to_bytes()
		
	def websend(self, url, cmd):
		"""
		url is the endpoint without '/'
		cmd is a dict
		"""
		try:
			with requests.post(self.url + url, data=cmd, headers=self.headers, verify = self.verify, proxies=self.proxies, auth=HTTPBasicAuth(self.device_id, self.password)) as r:
				if r.status_code != 200:
					logging.info('Web request returned with error! Error data: %s' % r.text)
					return None
				return r.text
		except Exception as e:
			logging.exception('Failed to perform web request!')
		
	def sr(self, cmd, throw = True):
		"""
		Sends a commend to the server to be relayed to the device
		"""
		packet_bytes = self.construct_packet(cmd)
		data = {
			'mcp' : packet_bytes.decode()
		}
		
		response = self.websend('gw_command', data)
		if not response:
			raise Exception('Request failed!')
		
		return MCPPacket.from_bytes(response.encode())
			
	def get_gw_status(self):
		data = {
			'cmd' : '',
			'id' : self.device_id,
		}
		
		response = self.websend('gw_onlinestatus', data)
		if not response:
			raise Exception('Request failed!')
		
		return json.loads(response)
		
	def list_gws(self):
		data = {
			'cmd' : 'validateDeviceId',
			'id' : self.device_id,
		}
		
		response = self.websend('gw_list', data)
		if not response:
			raise Exception('Request failed!')
		
		return json.loads(response)
		
	def login(self, username, password):
		logging.debug('login')
		cmd = MCPLogin.construct(username, password)
		
		resp = self.sr(cmd)
		logging.debug(resp)
		
		self.token = resp.payload.command.auth_token
		self.tag = resp.payload.command.auth_tag
		
	def get_user_rights(self):
		logging.debug('get_user_rights')
		cmd = MCPGetUserRights.construct()
		
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def jcmp(self, request):
		"""
		request needs to be a dict
		"""
		logging.debug('jcmp')
		cmd = JCMP.construct(request)
		resp = self.sr(cmd)
		logging.debug(resp)
	
	def get_wifi_state(self):
		logging.debug('get_wifi_state')
		cmd = MCPGetWifiState.construct()
		
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def scan_wifi(self):
		logging.debug('scan_wifi')
		cmd = MCPScanWifi.construct()
		
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def wifi_found(self):
		logging.debug('wifi_found')
		cmd = MCPWifiFound.construct()
		
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def get_gw_version(self):
		logging.debug('get_gw_version')
		cmd = MCPGETGWVersion.construct()
		
		resp = self.sr(cmd)
		logging.debug(resp)
		return resp
		
	def generic(self, cmd):
		logging.debug('generic')		
		resp = self.sr(cmd)
		print(resp)	
		
	def logout(self):
		logging.debug('logout')
		cmd = MCPLogout.construct()
		
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def add_user(self, username, password):
		logging.debug('add_user')
		cmd = MCPAddUser.construct(username, password)
		
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def change_password_of_user(self, user_id, newpassword):
		logging.debug('add_user')
		cmd = MCPChangePasswordOfUser.construct(user_id, newpassword)
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def change_password(self, newpassword):
		logging.debug('change_password')
		cmd = MCPChangePassword.construct(newpassword)
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def set_name(self, name):
		logging.debug('set_name')
		cmd = MCPSetName.construct(name)
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def debug(self):
		logging.debug('debug')
		cmd = MCPDebug.construct()
		resp = self.sr(cmd)
		logging.debug(resp)
		
	def get_mac(self):
		logging.debug('get_mac')
		cmd = MCPGetMAC.construct()
		resp = self.sr(cmd)
		logging.debug(resp)
		return resp
		
	def get_name(self):
		logging.debug('get_name')
		cmd = MCPGetName.construct()
		resp = self.sr(cmd)
		logging.debug(resp)
		return resp
		
	@staticmethod
	def discover_devices():
		pass
		
