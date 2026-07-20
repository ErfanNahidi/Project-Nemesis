from kerbad import logger
from kerbad.protocol.asn1_structs import KerberosResponse
from kerbad.common.target import KerberosTarget
from asysocks.unicomm.common.target import UniProto
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.packetizers import Packetizer


class KerberosPacketizer(Packetizer):
	def __init__(self, buffer_size = 65535):
		Packetizer.__init__(self, buffer_size)
		self.buffer_size = buffer_size
		self.in_buffer = b''
	
	def process_buffer(self):
		if len(self.in_buffer) > 4:
			length = int.from_bytes(self.in_buffer[:4], byteorder = 'big', signed = False)
			if len(self.in_buffer) >= length:
				data = self.in_buffer[4:4+length]
				self.in_buffer = self.in_buffer[length+4:]
				yield data
				
	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet


class KerberosPWChangePacketizer(Packetizer):
	def __init__(self, buffer_size = 65535):
		Packetizer.__init__(self, buffer_size)
		self.buffer_size = buffer_size
		self.in_buffer = b''
	
	def process_buffer(self):
		if len(self.in_buffer) > 4:
			length = int.from_bytes(self.in_buffer[:4], byteorder = 'big', signed = False)
			if len(self.in_buffer) >= length:
				data = self.in_buffer[4:4+length]
				self.in_buffer = self.in_buffer[length+4:]
				yield data
				
	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet

class AIOKerberosPWChangeClientSocket:
	def __init__(self, target:KerberosTarget):
		self.target = target
	
	def get_addr_str(self):
		return '%s:%d' % (self.target.get_hostname_or_ip(), self.target.port)
	
	async def sendrecv(self, data, throw:bool = False):
		client = None
		connection = None
		try:
			packetizer = KerberosPWChangePacketizer()
			client = UniClient(self.target, packetizer)
			connection = await client.connect()
			if self.target.protocol == UniProto.CLIENT_TCP:
				length = len(data).to_bytes(4, byteorder = 'big', signed = False)
				await connection.write(length + data)

				read_gen = connection.read()
				try:
					packet = await read_gen.__anext__()
					krb_message = packet
				finally:
					await read_gen.aclose()

			elif self.target.protocol == UniProto.CLIENT_UDP:
				raise Exception('Not implemented!')

			return krb_message
		finally:
			if connection is not None:
				await connection.close()

class AIOKerberosClientSocket:
	def __init__(self, target:KerberosTarget):
		self.target = target
	
	def get_addr_str(self):
		return '%s:%d' % (self.target.get_hostname_or_ip(), self.target.port)
	
	async def sendrecv(self, data, throw:bool = False):
		client = None
		connection = None
		try:
			packetizer = KerberosPacketizer()
			client = UniClient(self.target, packetizer)
			connection = await client.connect()
			if self.target.protocol == UniProto.CLIENT_TCP:
				length = len(data).to_bytes(4, byteorder = 'big', signed = False)
				await connection.write(length + data)

				# Use the async generator's __anext__ once instead of an
				# async-for loop with break — Python 3.13 emits
				# RuntimeWarning ("aclose was never awaited") and leaks the
				# generator if a break exits before the loop's normal close.
				read_gen = connection.read()
				try:
					packet = await read_gen.__anext__()
					krb_message = KerberosResponse.load(packet)
				finally:
					await read_gen.aclose()

			elif self.target.protocol == UniProto.CLIENT_UDP:
				raise Exception('Not implemented!')

			return krb_message
		finally:
			if connection is not None:
				await connection.close()


