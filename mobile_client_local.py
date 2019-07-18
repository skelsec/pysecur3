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
	#cli.get_mac()
	#cli.login('admin','0000')
	#cli.get_user_ids()
	#exit()
	
	#cli.scan_wifi()
	#b'\xee' <<< OK!!!
	#for i in range(255):
	#	cli.debug(bytes([i]))
	for i in range(239,255):
		cli.debug(bytes([i]))
	exit()
	
	
	#cli.login('admin','0000')
	#cli.get_user_ids()
	#cli.remove_user(3)
	#cli.get_user_ids()
	
	#cli.load_login(20736)
	
	#cli.logout()
	
	"""
	cmd = {'cmd':'GET_USERS'}
	cli.jcmp(cmd)
	
	cmd = {'cmd':'GET_VALUES'}
	cli.jcmp(cmd)
	
	
	#cli.wifi_found()
	"""
	
	#cli.add_user('haha','1111')
	
	#cli.login('admin','0000')
	#print(cli.token)
	#input()
	
	#cmd = MCPGetUserName.construct(0)
	#for i in range(10000,0xffffffff):
	#	cli.token = i
	#	resp = cli.sr(cmd, throw = False)
	#	if resp.payload.command_id != 1:
	#		print('[+] Found valid token ID! %d' % i)
	#		exit()
	#	
	#	if i % 0xffff == 0:
	#		print(i)
	
	
	
	#cli.get_user_name(0)
	#cli.debug()
	#cli.set_user_rights(1,[0,1,2])
	#cli.get_gw_version()
	#cli.get_mac()
	#cli.scan_wifi()
	#cli.add_user('test','1111')
	
	#cmd = {'cmd':'GET_GROUPS'}
	#cli.jcmp(cmd)
	#cli.get_user_rights()


	#cli.add_user('\x00','2222')
	"""
	cli.login('admin','0000')
	cli.get_user_rights()
	
	#cli.get_gw_version()
	cli.scan_wifi()
	#cli.wifi_found()
	#cmd = {'cmd':'GET_VALUES'}
	#cli.jcmp(cmd)
	
	#cmd = MCPGenericCommand.construct(96)
	#cli.generic(cmd)
	"""