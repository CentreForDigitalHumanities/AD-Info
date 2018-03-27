#!/usr/bin/python3

from ldap3 import Server, Connection, ALL, KERBEROS, SASL, LDAPKeyError
import re
import argparse

DESCRIPTION = 'Looks up which groups a certain solis id is a member of'
SOLIS_HELP = (
    "The Solis ID of the user you want to check. You can also "
    "search for a user by appending or prepending a '*' to "
    "your input"
    )
# Address of 
SERVER_ADDRESS = 'soliscom.uu.nl'
GROUP_FMT = "Solis-Id {} ({}) is member of the following {} UiL OTS groups:"
ALL_USERS = 'GG_GW_UiL-OTS_Labs_AllUsers'


def escape_ldap_input(string):
    """
    This function escapes the user input such that all values are seen as text,
    not filter instructions.

    TL;DR: prevents LDAP injection

    :param string string: The to be escaped string
    :return string: The escaped string
    """
    escape_vals = {
        '\\': r'\5c',
        r'(': r'\28',
        r'|': r'\7c',
        r'<': r'\3c',
        r'/': r'\2f',
        r')': r'\29',
        r'=': r'\3d',
        r'~': r'\7e',
        r'&': r'\26',
        r'>': r'\3e'
    }

    for x, y in escape_vals.items():
        string = string.replace(x, y)

    return string.strip(" ")


# Set up the argparser
parser = argparse.ArgumentParser(description=DESCRIPTION)
parser.add_argument('id', metavar='Solis-ID', type=str, help=SOLIS_HELP)

# Get the to search Common Name generally abbreviated as CN 
cn = parser.parse_args().id
cn = escape_ldap_input(cn)

# Constant for the allusers group

# This regex is used to reduce the groups DN to the first element, and
# filter out non-UiL groups
regex = re.compile(r'.*?=(.*?GW_UiL.*?),.*')

# Setup the connection through kerberos
server = Server(SERVER_ADDRESS, get_info=ALL, use_ssl=True)
connection = Connection(
    server,
    auto_bind=True,
    authentication=SASL,
    sasl_mechanism=KERBEROS,
    sasl_credentials=(True,)
    )

# force ssl connection active
connection.start_tls()

# Search for the given CN
connection.search(
    'dc=soliscom,dc=uu,dc=nl',
    '(cn={})'.format(cn),
    attributes=['cn', 'memberOf', 'displayName']
    )

# If there are no entries, display a warning
if not connection.entries:
    print('No user found for this solis ID!')

# Loop over the result entries
for entry in connection.entries:
    in_all_users = False

    # We store the groups here, instead of simply printing them
    # when finding them so we can detect if there are no UiL groups.
    groups = []

    try:
        # Loop over all groups
        for group in entry.memberOf:
            # Regex filter them
            shortname = regex.findall(group, re.IGNORECASE)

            # If we found something
            if len(shortname) == 1:
                # Add it
                groups.append(shortname[0])

                # Check if this is the allUsers group.
                # In that case we mark it as true
                if shortname[0] == ALL_USERS:
                    in_all_users = True

    except LDAPKeyError:
        pass

    print("-"*80)
    print(
        GROUP_FMT.format(
            entry.cn,
            entry.displayName,
            len(groups)
            )
        )

    # If there are no groups, we print None
    if groups: 
        # Otherwise, print them all!
        for group in groups:
            print("- {}".format(group))

    # Newline
    print()
    # Info message to say if this user is in the allUsers group
    if in_all_users:
        print('The user is already in the all users group')
    else:
        print('The user is NOT in the all user group')
    print("-"*80)
    if entry != connection.entries[len(connection.entries) - 1]:
        print() 
