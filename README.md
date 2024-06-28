# AD-Info
This script performs several pre-defined queries on the Active Directory LDAP server. 
Most of them specific for the ILS Labs, but increasingly modular.

# Requirements (Simple Auth)
- Python 3
- python3-ldap3

Note: the script will automatically fall back to simple auth if python3-gssapi isn't installed. You can force simple
auth by using the -s flag.

# Requirements (Kerberos Auth)
- Python 3
- python3-ldap3
- python3-kerberos
- python3-gssapi
- A linux machine with a configured Kerberos setup for Soliscom

# Authentication
By default, authentication on the LDAP is done through a kerberos ticket. If kerberos can't be imported, it will fall
back to username and password (simple auth). When running the application as root, you must use the -s flag to force 
simple authentication, as root cannot log in with kerberos.