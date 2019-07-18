import logging
import argparse

from pysecur3.device import *

"""
Emulates an arbitrary device on the LAN and also connects the BiSecur Home server and emulates a device there as well
Only some basic command handling is implemented, feel free to extend it!

"""

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Script for communicating the BiSecur Gateway via the BiSecur Home portal. Needs valid credentials!')
	parser.add_argument('mac', help='MAC address to spoof')
	parser.add_argument('cert', help='Client certificate obtained from an actual device')
	parser.add_argument('key', help='Client key obtained from an actual device')
	parser.add_argument('cacert', help='MAC address of the target BiSecur Gateway')
	args = parser.parse_args()
	
	logging.basicConfig(level=logging.DEBUG)
	
	mac_addr = bytes.fromhex(args.mac.replace(':','').replace(' ',''))
	
	dev = MCPDevice(mac_addr, args.cert, args.key, args.cacert, discoverable= True)
	
	loop = asyncio.get_event_loop()
	loop.run_until_complete(dev.run())
	loop.run_forever()
	loop.close()