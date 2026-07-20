
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import enum
import copy

from badldap.commons.target import MSLDAPTarget
from badldap.client import MSLDAPClient
from badldap.connection import MSLDAPClientConnection
from badauth.common.credentials import UniCredential

class LDAPConnectionFactory:
	"""
	The URL describes both the connection target and the credentials. This class creates all necessary objects to set up the client.
	
	:param url: 
	:type url: str
	"""

	help_epilog = """
	badldap URL Format: <protocol>+<auth>://<username>:<password>@<ip_or_host>:<port>/<tree>/?<param>=<value>
	<protocol> sets the ldap protocol following values supported:
		- ldap
		- ldaps
	<auth> can be omitted if plaintext authentication is to be performed (in that case it default to ntlm-password), otherwise:
		- ntlm-password
		- ntlm-nt
		- kerberos-password (dc option param must be used)
		- kerberos-rc4 / kerberos-nt (dc option param must be used)
		- kerberos-aes (dc option param must be used)
		- kerberos-keytab (dc option param must be used)
		- kerberos-ccache (dc option param must be used)
		- sspi-ntlm (windows only!)
		- sspi-kerberos (windows only!)
		- anonymous
		- plain
		- simple
		- sicily (same format as ntlm-nt but using the SICILY authentication)
	<tree>:
		OPTIONAL. Specifies the root tree of all queries
	<param> can be:
		- timeout : connction timeout in seconds
		- proxytype: currently only socks5 proxy is supported
		- proxyhost: Ip or hostname of the proxy server
		- proxyport: port of the proxy server
		- proxytimeout: timeout in secodns for the proxy connection
		- dc: the IP address of the domain controller, MUST be used for kerberos authentication
		- encrypt: enable encryption. Only for NTLM. DOESNT WORK WITH LDAPS
		- etype: Supported encryption types for Kerberos authentication. Multiple can be specified.
		- rate: LDAP paged search query rate limit. Will sleep for seconds between each new page. Default: 0 (no limit)
		- pagesize: LDAP paged search query size per page. Max: 1000. Default: 1000

	Examples:
	ldap://10.10.10.2 (anonymous bind)
	ldaps://test.corp (anonymous bind)
	ldap+sspi-ntlm://test.corp
	ldap+sspi-kerberos://test.corp
	ldap://TEST\\victim:<password>@10.10.10.2 (defaults to SASL GSSAPI NTLM)
	ldap+simple://TEST\\victim:<password>@10.10.10.2 (SASL SIMPLE auth)
	ldap+plain://TEST\\victim:<password>@10.10.10.2 (SASL SIMPLE auth)
	ldap+ntlm-password://TEST\\victim:<password>@10.10.10.2
	ldap+ntlm-nt://TEST\\victim:<nthash>@10.10.10.2
	ldap+kerberos-password://TEST\\victim:<password>@10.10.10.2
	ldap+kerberos-rc4://TEST\\victim:<rc4key>@10.10.10.2
	ldap+kerberos-aes://TEST\\victim:<aes>@10.10.10.2
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/?timeout=99&proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080&proxytimeout=44
	"""
	
	def __init__(self, credential:UniCredential = None, target:MSLDAPTarget = None ):
		self.credential = credential
		self.target = target

	@staticmethod
	def from_url(connection_url):
		target = MSLDAPTarget.from_url(connection_url)
		credential = UniCredential.from_url(connection_url)
		return LDAPConnectionFactory(credential, target)

	def get_credential(self) -> UniCredential:
		"""
		Creates a credential object
		
		:return: Credential object
		:rtype: :class:`UniCredential`
		"""
		return copy.deepcopy(self.credential)

	def get_target(self) -> MSLDAPTarget:
		"""
		Creates a target object
		
		:return: Target object
		:rtype: :class:`MSLDAPTarget`
		"""
		return copy.deepcopy(self.target)

	def get_client(self) -> MSLDAPClient:
		"""
		Creates a client that can be used to interface with the server
		
		:return: LDAP client
		:rtype: :class:`MSLDAPClient`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPClient(target, cred)

	def get_client_newtarget(self, hostname_or_ip:str, ip:str = None, port:int = None, new_domain:str = None, old_target_ip:str = None) -> MSLDAPClient:
		"""
		Creates a client with a different target that can be used to interface with the server
		"""
		cred = self.get_credential()
		target_old = self.get_target()
		old_proxies = copy.deepcopy(target_old.proxies)
		dc_ip = None
		if cred.protocol.value == 'KERBEROS' and new_domain and new_domain.upper() != cred.domain.upper():
			from asysocks.unicomm.common.target import UniTarget, UniProto
			# If it's krb creds and the new host hasn't the same REALM as the previous connection we'll have to request a ticket for the new REALM from the previous kdcc if there is one, if not from the previous dc ip if possible
			cred.cross_target = UniTarget(ip, 88, UniProto.CLIENT_TCP, proxies = old_proxies, dc_ip=ip)
			cred.cross_realm = new_domain
			dc_ip = old_target_ip

		target = MSLDAPTarget(
			ip if ip else hostname_or_ip, 
			port=port if port else target_old.port, 
			protocol=target_old.protocol, 
			tree=target_old.tree, 
			proxies=old_proxies, 
			timeout=target_old.timeout, 
			ldap_query_page_size=target_old.ldap_query_page_size, 
			ldap_query_ratelimit=target_old.ldap_query_ratelimit,
			dc_ip=dc_ip,
			hostname=hostname_or_ip
		)
		return MSLDAPClient(target, cred)

	def get_connection(self) -> MSLDAPClientConnection:
		"""
		Creates a connection that can be used to interface with the server
		
		:return: LDAP connection
		:rtype: :class:`MSLDAPClientConnection`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPClientConnection(target, cred)

	def get_connection_newtarget(self, hostname_or_ip:str) -> MSLDAPClientConnection:
		"""
		Creates a connection with a different target that can be used to interface with the server
		
		:return: LDAP connection
		:rtype: :class:`MSLDAPClientConnection`
		"""
		cred = self.get_credential()
		target_old = self.get_target()
		target = MSLDAPTarget(
			hostname_or_ip, 
			port=target_old.port, 
			protocol=target_old.protocol, 
			tree=target_old.tree, 
			proxies=copy.deepcopy(target_old.proxies), 
			timeout=target_old.timeout, 
			ldap_query_page_size=target_old.ldap_query_page_size, 
			ldap_query_ratelimit=target_old.ldap_query_ratelimit, 
			hostname=hostname_or_ip
		)
		return MSLDAPClientConnection(target, cred)
	
	@staticmethod
	def from_ldapconnection(connection:MSLDAPClientConnection):
		"""Creates a new LDAPConnectionFactory object from an existing SMBConnection object"""
		"""This is useful when you have a connection object, but you need to create a new connection with the same credentials"""
		return LDAPConnectionFactory(copy.deepcopy(connection.credential), copy.deepcopy(connection.target))

		
	def __str__(self):
		t = '==== LDAPConnectionFactory ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t

# ADSCAN log-hygiene: the upstream ``if __name__ == '__main__':`` self-test
# harness was removed. It printed ``str(creds)`` (a raw credential dump to
# stdout, bypassing telemetry) and called ``input()`` (which would hang any
# non-interactive run). It was never reached on import; deleting it removes a
# latent credential-exfiltration path with zero runtime value.
