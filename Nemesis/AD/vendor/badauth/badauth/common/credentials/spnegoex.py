from typing import List
from badauth.common.credentials import UniCredential
from badauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from badauth.common.subprotocols import SubProtocol
from badauth.common.subprotocols import SubProtocolNative

class SPNEGOEXCredential(UniCredential):
	def __init__(self, credentials:List[UniCredential] = [], subprotocol:SubProtocol = SubProtocolNative()):
		UniCredential.__init__(self, protocol = asyauthProtocol.SPNEGOEX, subprotocol=subprotocol)
		self.credentials = credentials
	
	def build_context(self, *args, **kwargs):
		if self.subprotocol.type == asyauthSubProtocol.NATIVE:
			from badauth.protocols.spnego.client.native import SPNEGOClientNative
			sspi_ctx = SPNEGOClientNative(self)
			for credential in self.credentials:
				context = credential.build_context()
				if credential.protocol == asyauthProtocol.KERBEROS:
					sspi_ctx.add_auth_context('MS KRB5 - Microsoft Kerberos 5', context)
				elif credential.protocol == asyauthProtocol.NTLM:
					sspi_ctx.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', context)
				else:
					raise Exception('Authentication protocol "%s" is not supported for SPNEGO' % credential.protocol)
			return sspi_ctx

		else:
			raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)