from pysecur3.MCP import *
import argparse

if __name__ == '__main__':
	
	parser = argparse.ArgumentParser(description='Script to discover BiSecur Gateways on your local network')
	parser.add_argument('-i', '--listen-ip', default='', help='IP to listen incoming packets on. Default: all available ips')
	parser.add_argument('-b', '--broadcast-ip', default='255.255.255.255', help='Broadcast address. Default: 255.255.255.255')
	args = parser.parse_args()	

	print('DISCOVERY MODE!')

	disc = MCPDiscover(args.listen_ip, args.broadcast_ip)
	disc.run()
			
	if len(disc.devices) > 0:
		for ip in disc.devices:
			print('Found device on address: %s, device attributes: %s ' % (ip, disc.devices[ip]))
	else:
		print('No devices found! Did you get the IP and broadcast correct?')