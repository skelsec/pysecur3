import logging
import argparse

from pysecur3.webclient import MCPWebClient

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Script for communicating the BiSecur Gateway via the BiSecur Home portal. Needs valid credentials!')
	parser.add_argument('deviceid', help='Device ID obtained from BiSecur Home portal')
	parser.add_argument('password', help='Password for the device ID obtained from BiSecur Home portal')
	parser.add_argument('gateway_mac', help='MAC address of the target BiSecur Gateway')
	args = parser.parse_args()
	
	
	logging.basicConfig(level=logging.INFO)
	
	device_id = args.deviceid.replace('-','').replace(':','')
	password = args.password
	gateway_mac = bytes.fromhex(args.gateway_mac.replace(':','').replace(' ',''))
	
	cli = MCPWebClient(device_id, password, gateway_mac)
	
	print('Listing available gateways for the account..')
	gws = cli.list_gws()
	print(gws)
	
	print('Listing status of the available gateways')
	gwstatus = cli.get_gw_status()
	print(gwstatus)
	
	print('Getting MAC address of the selected gateway')
	mac = cli.get_mac()
	print(mac)
	
	print('Getting gateway name')
	name = cli.get_name()
	print(name)
	
	print('Getting gateway name')
	cli.login('alma','password')
	print(name)
	
	#print('Getting version number of the selected gateway')
	#version = cli.get_gw_version()
	#print(version)