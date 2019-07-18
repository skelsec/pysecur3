import asyncio
import logging

from MCP import *

class MCPScanner:
	def __init__(self, target_file, src_mac, timeout = 3, loop = asyncio.get_event_loop()):
		self.loop = loop
		self.target_file = target_file
		self.src_mac = src_mac
		self.dst_mac = b'\xFF\xFF\xFF\xFF\xFF\xFF'
		self.timeout = timeout
		
		self.tag = 0
		self.token = 0
		
		self.targets = []
		self.results = []
		
		self.scanner_tasks = []
		
		cmd = MCPGETGWVersion.construct()
		payload = MCP.construct(cmd, tag = self.tag, token = self.token)		
		packet = MCPPacket.construct(self.src_mac, self.dst_mac, payload)
		self.packet_bytes = packet.to_bytes()
		
	async def scan_ip(self, ip, port = 4000):
		
		try:
			fut = asyncio.open_connection(ip, port)
			reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
			
			writer.write(self.packet_bytes)
			await writer.drain()
			
			fut = reader.readexactly(28)
			buff = await asyncio.wait_for(fut, timeout=self.timeout)
			total_len = int.from_bytes(bytes.fromhex(buff[:28].decode())[12:14], byteorder = 'big', signed = False)
			total_len = (total_len * 2) + 13*2 # because it's hex encoded on the wire + 1 byte CRC + 2 times MAC addr hex encoded
			
			fut = reader.readexactly(total_len - len(buff))
			buff += await asyncio.wait_for(fut, timeout=self.timeout)
			
			logging.debug('Data recieved: %s' % buff)
			response_packet = MCPPacket.from_bytes(buff)
			logging.debug('Response from IP %s: %s' % (ip, repr(response_packet)))
			self.results.append((ip, response_packet))
			
		
		except Exception as e:
			logging.debug('Exception when scanning IP %s Data: %s' % (ip, str(e)))
		finally:
			try:
				writer.close()
			except:
				pass
	async def run(self):
		with open(self.target_file,'r') as f:
			for line in f:
				self.targets.append(line.strip())
		
		
		for i in range(0,len(self.targets),100):
			logging.debug('Scanning range %d - %d' % (i, i + 100))
			for ip in self.targets[i:i+100]:
				fut = asyncio.gather(self.scan_ip(ip))
				self.scanner_tasks.append(fut)
				
			await asyncio.gather(*self.scanner_tasks)


if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)
	
	output_file = 'scanner_results.txt'
	targets_file = 'C:\\Users\\picdev\\Desktop\\garage_targets.txt'
	src_mac = b'\xFF\xFF\xFF\xFF\xFF\xFF'
	
	scanner = MCPScanner(targets_file, src_mac)
	loop = asyncio.get_event_loop()
	loop.run_until_complete(scanner.run())
	loop.close()
	
	print('Scanner finished, writing results to file!')
	with open(output_file, 'wb') as o:
		for result in scanner.results:
			try:
				o.write(b'%s\t%s \r\n'% (result[0].encode(), result[1].payload.command.gw_version.encode()))
			except:
				pass
	print('Done!')