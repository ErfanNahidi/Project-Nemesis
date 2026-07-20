
from badauth.protocols.credssp.messages.asn1_structs import *

## this is not implemented yet!

"""
typedef struct _NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL {
      ULONG Version; 
      ULONG Flags;
      MSV1_0_CREDENTIAL_KEY_TYPE reserved;
      MSV1_0_CREDENTIAL_KEY reserved;
      ULONG reservedsize;
      [size_is(reservedSize)] UCHAR* reserved;
    } NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL; 




"""
import enum
import io

class MSV1_0_CREDENTIAL_KEY_TYPE(enum.Enum):
	InvalidCredKey = 0 #        // reserved 
	IUMCredKey = 1 #             // reserved 
	DomainUserCredKey = 2 #     
	LocalUserCredKey = 3 #      // For internal use only - should never be present in MSV1_0_REMOTE_ENCRYPTED_SECRETS
	ExternallySuppliedCredKey = 4 # // reserved

class NRSC_FLAG(enum.IntFlag):
	LMOWF = 1
	NTOWF = 2
	CREDKEY_PRESENT = 8

class NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL:
	def __init__(self):
		self.Version:int = None
		self.Flags:int = None
		self.KeyType:MSV1_0_CREDENTIAL_KEY_TYPE = None
		self.Key:bytes = None
		self.reservedSize: int = None
		self.reserved6: bytes = None #size is 'reservedSize'

		
	def to_bytes(self):
		t  = self.Version.to_bytes(4, byteorder='little', signed = False)
		t += self.Flags.to_bytes(4, byteorder='little', signed = False)
		t += self.KeyType.value.to_bytes(4, byteorder='little', signed = False)
		t += self.Key
		t += len(self.reserved6).to_bytes(4, byteorder='little', signed = False)
		t += self.reserved6

		return t

	@staticmethod
	def from_bytes(bbuff: bytes):
		return NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff: io.BytesIO):
		msg = NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL()
		msg.Version = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.Flags = NRSC_FLAG(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		msg.Key = buff.read(20)
		msg.KeyType = MSV1_0_CREDENTIAL_KEY_TYPE(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		msg.reservedSize = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.reserved6 = buff.read(msg.reservedSize)
		return msg

	def __repr__(self):
		t = '==== NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL ====\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], enum.IntFlag):
				value = self.__dict__[k]
			elif isinstance(self.__dict__[k], enum.Enum):
				value = self.__dict__[k].name
			else:
				value = self.__dict__[k]
			t += '%s: %s\r\n' % (k, value)
		return t
