# UiL OTS AD group checker
This script queries the Solis-AD to check which UiL OTS Lab groups a certain user is a member of.
It also displays an extra message to say if the user is a member of the AllUsers group.

# Requirements (Kerberos Auth)
- Python 3
- python3-ldap3
- python3-kerberos
- python3-gssapi
- A linux machine with a configured Kerberos for soliscom
(Should already be installed on the lab PC's)

# Requirements (Simple Auth)
- Python 3
- python3-ldap3

Note: the script will automatically fall back to simple auth if python3-gssapi isn't installed. You can force simple
auth by using the -s flag.

# Authentication
By default, authentication on the LDAP is done through a kerberos ticket. If kerberos can't be imported, it will fall
back to username and password (simple auth). When running the application as root, you must use the -s flag to force 
simple authentication, as root cannot log in with kerberos.