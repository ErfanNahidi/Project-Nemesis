from setuptools import setup, find_packages
import re

VERSIONFILE="badldap/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))


setup(
	# Application name:
	name="badldap",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",
    
	# Maintainer details:
	maintainer="Baptiste Crépin",
	maintainer_email="baptiste@cravaterouge.com",
    
	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/CravateRouge/badldap",

	zip_safe = False,
	#
	# license="LICENSE.txt",
	description="Python library to play with MS LDAP",
	long_description="Python library to play with MS LDAP",

	# long_description=open("README.txt").read(),
	python_requires='>=3.7',
	classifiers=[
		"Programming Language :: Python :: 3.7",
		"Programming Language :: Python :: 3.8",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
		'unicrypto>=0.0.12',
		'badauth>=0.1.6',
		'asysocks>=0.2.18',
		'asn1crypto>=1.3.0',
		'winacl>=0.1.8',
		'prompt-toolkit>=3.0.2',
		'tqdm',
		'wcwidth',
		'tabulate',
		'unidns>=0.0.3',
        'dnspython>=2.7.0'
	],
	entry_points={
		'console_scripts': [
			'badldap = badldap.examples.msldapclient:main',
            'badldap-bloodhound = badldap.examples.msldapbloodhound:main',
		],
	}
)
