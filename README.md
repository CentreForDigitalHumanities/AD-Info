# UiL OTS AD group checker
This script queries the Solis-AD to check which UiL OTS Lab groups a certain user is a member of.
It also displays an extra message to say if the user is a member of the AllUsers group.

# Requirements
- Python 3
- python3-ldap3
- python3-kerberos
- python3-gssapi
- A linux machine with a configured Kerberos for soliscom
(Should already be installed on the lab PC's)

# Authentication
