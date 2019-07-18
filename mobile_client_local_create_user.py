import logging
import argparse

from pysecur3.client import MCPClient

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Script implementing a client for BiSecur Gateway')
	parser.add_argument('ip', help='IP of the gateway')
	parser.add_argument('mac', help='MAC address of the gateway')
	parser.add_argument('-s', '--src-mac', default = 'FF:FF:FF:FF:FF:FF', help='source mac address. can be anything')
	args = parser.parse_args()
	
	logging.basicConfig(level=logging.DEBUG)

	src_mac = bytes.fromhex(args.src_mac.replace(':',''))
	dst_mac = bytes.fromhex(args.mac.replace(':',''))
	
	cli = MCPClient(args.ip, 4000, src_mac, dst_mac)
	#cli.add_user('haha2','1111', b'\xff')
	cli.login('haha','1111')
	cli.get_user_ids()
	cli.get_user_name(2)
	exit()