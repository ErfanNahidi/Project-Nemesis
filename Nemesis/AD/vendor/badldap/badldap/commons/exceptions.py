
from badldap.protocol.messages import resultCode
from badldap.wintypes.winerror import WINERROR
import re


LDAPResultCodeLookup ={
	0  : 'success',
	1  : 'operationsError',
	2  : 'protocolError',
	3  : 'timeLimitExceeded',
	4  : 'sizeLimitExceeded',
	5  : 'compareFalse',
	6  : 'compareTrue',
	7  : 'authMethodNotSupported',
	8  : 'strongerAuthRequired',
	10 : 'referral',
	11 : 'adminLimitExceeded',
	12 : 'unavailableCriticalExtension',
	13 : 'confidentialityRequired',
	14 : 'saslBindInProgress',
	16 : 'noSuchAttribute',
	17 : 'undefinedAttributeType',
	18 : 'inappropriateMatching',
	19 : 'constraintViolation',
	20 : 'attributeOrValueExists',
	21 : 'invalidAttributeSyntax',
	32 : 'noSuchObject',
	33 : 'aliasProblem',
	34 : 'invalidDNSyntax',
	36 : 'aliasDereferencingProblem',
	48 : 'inappropriateAuthentication',
	49 : 'invalidCredentials',
	50 : 'insufficientAccessRights',
	51 : 'busy',
	52 : 'unavailable',
	53 : 'unwillingToPerform',
	54 : 'loopDetect',
	64 : 'namingViolation',
	65 : 'objectClassViolation',
	66 : 'notAllowedOnNonLeaf',
	67 : 'notAllowedOnRDN',
	68 : 'entryAlreadyExists',
	69 : 'objectClassModsProhibited',
	71 : 'affectsMultipleDSAs',
	80 : 'other',
}
LDAPResultCodeLookup_inv = {v: k for k, v in LDAPResultCodeLookup.items()}

class LDAPServerException(Exception):
	def __init__(self, resultname, diagnostic_message, message = None):
		self.resultcode = LDAPResultCodeLookup_inv[resultname]
		self.resultname = resultname
		self.diagnostic_message = diagnostic_message
		self.message = format_ad_ldap_error(diagnostic_message, self.resultname, getattr(self, "dn", None))
		super().__init__(self.message)

class LDAPSearchException(LDAPServerException):
	def __init__(self, resultcode, diagnostic_message):
		message = 'LDAP Search failed! Result code: "%s" Reason: "%s"' % (resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPBindException(LDAPServerException):
	def __init__(self, resultcode, diagnostic_message):
		message = 'LDAP Bind failed! Result code: "%s" Reason: "%s"' % (resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPAddException(LDAPServerException):
	def __init__(self, dn, resultcode, diagnostic_message):
		self.dn = dn
		message = 'LDAP Add operation failed on DN %s! Result code: "%s" Reason: "%s"' % (self.dn, resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPModifyException(LDAPServerException):
	def __init__(self, dn, resultcode, diagnostic_message):
		self.dn = dn
		message = 'LDAP Modify operation failed on DN %s! Result code: "%s" Reason: "%s"' % (self.dn, resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPDeleteException(LDAPServerException):
	def __init__(self, dn, resultcode, diagnostic_message):
		self.dn = dn
		message = 'LDAP Delete operation failed on DN %s! Result code: "%s" Reason: "%s"' % (self.dn, resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPModifyDNException(LDAPServerException):
	def __init__(self, dn, resultcode, diagnostic_message):
		self.dn = dn
		message = 'LDAP ModifyDN operation failed on DN %s! Result code: "%s" Reason: "%s"' % (self.dn, resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)


def format_ad_ldap_error(diag_raw: bytes, resultcode: str, dn: str = None) -> str:
	diag_msg = diag_raw.decode('utf-8', errors='ignore')

	object_error = ''
	if dn:
		# 	# If LDAP error on DN there is probably an attribute specified to extract
		m_attr = re.search(r'Att\s+[0-9A-Fa-f]+\s+\(([^)]+)\)', diag_msg)
		attribute = f' {m_attr.group(1)}' if m_attr else ''
		object_error = f"for {dn} (Attr{attribute}) "

	# Find first matching WINERROR code
	code_name = None
	code_message = None
	for hexstr in re.findall(r'\b[0-9A-Fa-f]{8}\b', diag_msg):
		try:
			code_int = int(hexstr, 16)
		except ValueError:
			continue
		info = WINERROR.get(code_int)
		if info:
			code_name = info.get("code")
			code_message = info.get("message")
			break

	reason = None
	if code_name:
		reason = f"({code_name}) {code_message}"
	else:
		m_reason = re.search(r'(problem[^,]+),\s+data 0([^\n]*)', diag_msg)
		raw_reason = ''.join(m_reason.groups()) if m_reason else None
		reason = raw_reason if raw_reason else diag_msg

	return f"{resultcode} {object_error}— Reason:{reason}"

