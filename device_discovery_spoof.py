import time
from multiprocessing import freeze_support
from pysecur3.MCP import *
import argparse

if __name__ == '__main__':
	freeze_support()
	parser = argparse.ArgumentParser(description='Script to spoof mobile client by faking a BiSecur Gateway on the local network')
	parser.add_argument('-m', '--mac-address', default='00:00:00:00:00:00', help='Spoofed device MAC address. Default: 00:00:00:00:00:00')
	args = parser.parse_args()
	
	logging.basicConfig(level=logging.DEBUG)
	
	
	mac_addr = bytes.fromhex(args.mac_address.replace(':','').replace(' ',''))
	device_attr = MCPDeviceAttrs.construct(mac_addr)

	disc = MCPDiscoverResponder(device_attr)
	disc.daemon = True
	disc.start()
	
	print('Spoof responder started, waiting indefinitely. Press CTRL+C to stop')
	while True:
		time.sleep(1)