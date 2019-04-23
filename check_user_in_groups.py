#!/usr/bin/python3

from ldap3 import Server, Connection, ALL, KERBEROS, SASL, LDAPKeyError
import re
import argparse

DESCRIPTION = 'Looks up which groups a certain user is a member of'
SOLIS_HELP = (
    "The Solis ID/Email of the user you want to check. You can also "
    "search for a user by appending or prepending a '*' to "
    "your input."
    )
EMAIL_HELP = (
    "This option can be used to search for/locate a user using his/her "
    "email-address instead of a Solis-ID."
)
ALL_HELP = (
    "This option can be used to view all the groups the user is a member of, "
    "instead of only the UiL-OTS groups."
)
# Address of
SERVER_ADDRESS = 'soliscom.uu.nl'
GROUP_FMT = "Solis-ID {} is member of the following {} UiL OTS groups:"
ALL_USERS = 'GG_GW_UiL-OTS_Labs_AllUsers'


def print_user_attribute(data, label, attribute):
    """This function prints a given attribute, and handles any LDAPKeyErrors"""
    try:
        value = getattr(data, attribute)
        print("{}{}".format(label, value))
    except LDAPKeyError:
        print("{}".format(label))


def print_error(string: str):
    """
    Print errors with a nice red color. (Or whatever color is used for FAIL)
    """
    print("\033[91m{}\x1b[0m".format(string))


def print_ok(string: str):
    """
    Print errors with a nice green color. (Or whatever color is used for OKGREEN)
    """
    print("\033[92m{}\x1b[0m".format(string))


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
parser.add_argument('id', metavar='Search query', type=str, help=SOLIS_HELP)
parser.add_argument('-e', '--email', help=EMAIL_HELP, action='store_true')
parser.add_argument('-a', '--all', help=ALL_HELP, action='store_true')

# Get the run config from the argparser
arguments = parser.parse_args()
search_query_argument = arguments.id
use_email = arguments.email
show_all_groups = arguments.all

# Escape the search query argument, to prevent LDAP injections.
search_query_argument = escape_ldap_input(search_query_argument)

# Build the correct search query
if use_email:
    search_query = '(mail={})'.format(search_query_argument)
else:
    search_query = '(cn={})'.format(search_query_argument)

# This regex is used to reduce the groups DN to the first element, and
# filter out non-UiL groups
main_regex = re.compile(r'.*?=(.*?GW_UiL.*?),.*')

# This regex is used to find the ITS-made groups for the new ITS DFS project
# folders (which follow a different naming convention)
its_regex = re.compile(r'.*?=(.*?R_FS_Research-GW-Projects.*?),.*')

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
    search_query,
    attributes=[
        'cn',
        'memberOf',
        'displayName',
        'mail',
        'title',
        'department',
        'telephoneNumber'
    ]
)

# If there are no entries, display a warning
if not connection.entries:
    if use_email:
        print_error('No user found with this email address!')
    else:
        print_error('No user found for this solis ID!')

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
            shortname_main = main_regex.findall(group, re.IGNORECASE)
            shortname_its = its_regex.findall(group, re.IGNORECASE)

            # To check if we already added this one, used to prevent
            # duplicates when using --all
            added = False

            for shortname in [shortname_main, shortname_its]:
                # If we found something
                if len(shortname) == 1:
                    # Add it
                    groups.append(shortname[0])
                    added = True

                    # Check if this is the allUsers group.
                    # In that case we mark it as true
                    if shortname[0] == ALL_USERS:
                        in_all_users = True
            # If we want to show all groups, add this group anyway.
            if not added and show_all_groups:
                groups.append(group)

    except LDAPKeyError:
        pass

    print("-"*80)
    # Print user info
    print("User info:")
    print_user_attribute(entry, 'Solis-ID:\t', 'cn')
    print_user_attribute(entry, 'Name:\t\t', 'displayName')
    print_user_attribute(entry, 'Email\t\t', 'mail')
    print_user_attribute(entry, 'Phone:\t\t', 'telephoneNumber')
    print_user_attribute(entry, 'Department:\t', 'department')
    print_user_attribute(entry, 'Position:\t', 'title')

    # Newline for readability
    print()

    # Start printing groups
    print(
        GROUP_FMT.format(
            entry.cn,
            len(groups)
            )
        )

    # If there are no groups, we print None
    if groups: 
        # Otherwise, print them all!
        for group in groups:
            print("- {}".format(group))
    else:
        print('- None')

    # Newline
    print()
    # Info message to say if this user is in the allUsers group
    if in_all_users:
        print_ok('The user is already in the all users group')
    else:
        print_error('The user is NOT in the all user group')
    print("-"*80)
    if entry != connection.entries[len(connection.entries) - 1]:
        print() 
