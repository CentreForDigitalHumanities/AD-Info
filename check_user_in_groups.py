#!/usr/bin/python3
from typing import List, Set, Tuple

from ldap3 import Entry, Server, Connection, ALL, SIMPLE

# In newer versions Exceptions are located in: ldap3.core.exceptions
try:
    from ldap3 import LDAPKeyError
except ImportError as e:
    from ldap3.core.exceptions import LDAPKeyError
import re
import argparse
import getpass

DESCRIPTION = (
    'Queries the AD for certain info. Note: authentication and format options '
    'are always available, but not shown on sub-commands. These flags must '
    'also be supplied BEFORE the command.'
)

PERSON_DESCRIPTION = (
    'Looks up which groups a certain user is a member of'
)

PERSON_HELP = 'Search account info'

GROUP_DESCRIPTION = (
    'Queries the AD for group info for the given group. Can also show all UiL '
    'OTS groups if no group was supplied'
)

GROUP_HELP = 'Search group info'

STALE_DESCRIPTION = (
    'Runs through all project folder groups and gives several different '
    'warnings for folders that might need cleaning up in some way or another'
)

STALE_HELP = 'Analyse project folders for abandoned folders'

CUSTOM_DESCRIPTION = (
    'Allows you to run custom LDAP queries. WARNING! BE CAREFULL! This really '
    'isn\'t a great idea unless you really need to do something manually!\n '
    'Additionally, this only allows search queries, for safety.'
)

CUSTOM_HELP = 'Run a custom LDAP query'

CUSTOM_QUERY_HELP = (
    "The LDAP query to run"
)

CUSTOM_BASE_HELP = (
    "The base DN to start searching from. Defaults to 'dc=soliscom,dc=uu,dc=nl'"
)

CUSTOM_ATTR_HELP = (
    'The entry attributes to retrieve from the LDAP. Note: to retrieve '
    'multiple attributes, separate them with spaces. Defaults to [\'CN\']'
)

SOLIS_HELP = (
    "The Solis ID/Email of the user you want to check. You can also "
    "search for a user by appending or prepending a '*' to "
    "your input."
)

GROUP_QUERY_HELP = (
    "The name of the group you want to check. You can also "
    "search for a group by providing just a part of it's name. If this "
    "argument is omitted, it will print a list of all UiL OTS groups"
)

GROUP_RAW_HELP = (
    "By default, a UiL specific prefix will be added to your search query if "
    "none is detected. This flag will override that behaviour. This will "
    "allow you to search for any AD group. Note: this has some performance "
    "implications, as it will effectively search everything."
)

EMAIL_HELP = (
    "This option can be used to search for/locate a user using his/her "
    "email-address instead of a Solis-ID."
)
ALL_HELP = (
    "This option can be used to view all the groups the user is a member of, "
    "instead of only the UiL-OTS groups."
)

NO_FORMAT_HELP = (
    "By default, group names will be shortened by removing it's LDAP "
    "hierarchy. This option will force this behaviour off."
)

SIMPLE_AUTH_HELP = (
    "This will force simple-auth over kerberos auth. (Simple auth means using "
    "username and password.)"
)
USERNAME_HELP = (
    "This option can be used with simple auth to provide a username. Implies "
    "-s."
)
# Address of
SERVER_ADDRESS = 'soliscom.uu.nl'
GROUP_FMT = "Solis-ID {} is member of the following {} UiL OTS groups:"
ALL_USERS = 'GG_GW_UiL-OTS_Labs_AllUsers'


def print_user_attribute(data, label, attribute) -> None:
    """This function prints a given attribute, and handles any LDAPKeyErrors"""
    try:
        value = getattr(data, attribute)
        print("{}{}".format(label, value))
    except LDAPKeyError:
        print("{}".format(label))


def print_error(string: str) -> None:
    """
    Print errors with a nice red color. (Or whatever color is used for FAIL)
    """
    print("\033[91m{}\x1b[0m".format(string))


def print_ok(string: str) -> None:
    """
    Print errors with a nice green color. (Or whatever color is used for OKGREEN)
    """
    print("\033[92m{}\x1b[0m".format(string))


def escape_ldap_input(string: str) -> str:
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


def get_connection(argparse_arguments) -> Connection:
    """This method will create our connection object.

    It will try to use kerberos first, falling back to simple auth when kerberos
    auth is not available. This can be overriden by --username or --simple-auth

    :param argparse_arguments: Info from argparse
    :return:
    """
    default_args = {
        'auto_bind': True
    }

    # Always use simple auth if a username is specified
    if argparse_arguments.username or argparse_arguments.simple_auth:
        connection_args = get_simple_auth_connection_args(
            default_args,
            argparse_arguments
        )
    else:
        try:
            # First try to get the Kerberos auth
            connection_args = get_kerberos_connection_args(default_args)
        except ModuleNotFoundError:
            # No Kerberos found, fall back to simple auth
            connection_args = get_simple_auth_connection_args(
                default_args,
                argparse_arguments
            )

    # Create the connection
    return Connection(
        server,
        **connection_args
    )


def get_kerberos_connection_args(default_args: dict) -> dict:
    """Builds a dict with ldap connection arguments for kerberos auth.

    :param default_args: Default connection arguments
    :raises ModuleNotFound if kerberos related dependencies aren't installed.
    :return: The connection args
    """
    # These imports fail if kerberos is not installed
    from ldap3 import KERBEROS, SASL
    import gssapi

    default_args.update({
        'authentication':   SASL,
        'sasl_mechanism':   KERBEROS,
        'sasl_credentials': (True,),
    })

    return default_args


def get_simple_auth_connection_args(default_args, argparse_arguments) -> dict:
    """Builds a dict with ldap connection arguments for simple auth.

    :param default_args: Default connection arguments
    :param argparse_arguments: Info from argparse
    :return: The connection args
    """
    user, password = get_simple_auth_cred(argparse_arguments)

    default_args.update({
        'authentication': SIMPLE,
        'user':           user,
        'password':       password
    })

    return default_args


def get_simple_auth_cred(argparse_arguments) -> tuple:
    """This function returns simple auth credentials.

    Username will be taken from the argparse arguments if present, otherwise
    the script will prompt for it.

    Password is always prompted.

    :param argparse_arguments: Info from argparse
    :return: Username and Password
    """
    # Use the username argument if supplied, otherwise prompt for the username
    user = argparse_arguments.username or input('Username: ')

    # Usernames should be @soliscom.uu.nl, but for human convinience we append
    # it if it's not present
    if not user.endswith('@soliscom.uu.nl'):
        user = "{}@soliscom.uu.nl".format(user)

    # Use getpass to get the password
    password = getpass.getpass()

    return user, password


def _search_user(connection, argparse_arguments) -> None:
    """Handles the person command"""
    search_query_argument = argparse_arguments.id
    use_email = argparse_arguments.email
    show_all_groups = argparse_arguments.all

    # Escape the search query argument, to prevent LDAP injections.
    search_query_argument = escape_ldap_input(search_query_argument)

    # Build the correct search query
    if use_email:
        search_query = '(mail={})'.format(search_query_argument)
    else:
        search_query = '(cn={})'.format(search_query_argument)

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
                        if argparse_arguments.no_format:
                            groups.append(group)
                        else:
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

        print("-" * 80)
        # Print user info
        print("User info:")
        print_user_attribute(entry, 'DN:\t\t', 'entry_dn')
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
        print("-" * 80)
        if entry != connection.entries[len(connection.entries) - 1]:
            print()


def _search_group(connection, argparse_arguments) -> None:
    """This function handles the group command"""

    # Search for the given CN
    connection.search(
        'DC=soliscom,DC=uu,DC=nl',
        _build_group_search_query(argparse_arguments),
        attributes=[
            'cn',
            'member',
        ]
    )

    if not connection.entries:
        print_error('No group found')
    else:
        if argparse_arguments.id:
            _print_group_details(connection.entries)
        else:
            _print_group_list(connection.entries)


def _build_group_search_query(argparse_arguments) -> str:
    """Builds the LDAP query to search for a group"""
    arg = argparse_arguments.id

    # If we have a search query, format it into a LDAP query
    if arg:
        # Escape the string
        arg = escape_ldap_input(arg)
        # If we already have the right prefix, create a simple query
        # This is intended for when the entire CN is given as a search query
        if arg.startswith('GW_UIL') or arg.startswith('GG_GW_UiL') or \
           arg.startswith('R_FS') or argparse_arguments.raw_search:
            search_query = '(cn={})'.format(arg)
        else:
            # If we don't, add the prefixes for less garbage
            # This is intended for searching using incomplete names
            search_query = "(|(cn=*GW_UiL*{0}*)(" \
                           "cn=*R_FS_Research-GW-Project*{0}*_C))".format(arg)
    else:
        # If no search query is given, use this query to find all UiL OTS groups
        search_query = "(|(cn=*GW_UiL*)(cn=*R_FS_Research-GW-Projects*_C))"

    return search_query


def _print_group_details(entries) -> None:
    """Prints the name and members of a list of groups"""
    total = len(entries)
    for i, entry in enumerate(entries):
        print("-" * 80)

        print_user_attribute(entry, 'DN:\t', 'entry_dn')
        print_user_attribute(entry, 'Group:\t', 'cn')

        print('Members:')
        for member in entry.member:
            print(" - {}".format(member))

        print()
        print("-" * 80)
        # Only add a newline if this isn't the last group
        if (i + 1) != total:
            print()


def _print_group_list(entries) -> None:
    """Prints a list of all groups"""
    print("All UiL OTS Groups:")
    for entry in entries:
        print(" - {}".format(entry.cn))

    print("\nTotal: {}".format(len(entries)))


def _search_stale_users_or_groups(connection, argparse_arguments) -> None:
    """This function handles the group command"""

    # Search for the given CN
    connection.search(
        'OU=FS,OU=Resource,OU=NonProvisioned,OU=Groups,OU=UU,DC=soliscom,DC=uu,DC=nl',
        "(cn=R_FS_Research-GW-Projects-*)",
        attributes=[
            'cn',
            'member',
        ]
    )

    if not connection.entries:
        print_error('No groups found. This should be impossible!')
        exit(1)

    entries = _group_groups(connection.entries)
    _process_groups(entries)


def _group_groups(entries: List[Entry]) -> List[Tuple[str, Entry, Entry]]:
    entries = sorted(entries)
    groups = []

    for i in range(0, len(entries), 2):
        c = entries[i]
        r = entries[i + 1]

        # Check if what we think is the _C group is actually the _C group
        if not c.cn[0].endswith("_C"):
            print_error("Could not group groups, first group is not change "
                        "group")
            exit(1)

        # Get the name of both groups
        name = c.cn[0][:-2]
        # Ensure that we have corresponding groups
        if not r.cn[0] == f"{name}_R":
            print_error("Could not group groups, read only group did not "
                        "match change group")
            exit(1)

        groups.append((name, c, r))

    return groups


def _process_groups(groups: List[Tuple[str, Entry, Entry]]) -> None:
    for name, change, read_only in groups:
        reasons = []

        if len(change.member) == 0 and len(read_only.member) == 0:
            reasons.append("Group has no members")

        reasons.extend(_check_stale_users(change))
        reasons.extend(_check_stale_users(read_only))

        if len(reasons) != 0:
            print("-" * 80)
            print(f"Name:\t {name}\n")
            print("Users:")
            print("Change rights:")
            print(*[f"- {m}" for m in change.member], sep="\n")
            print("Read-only rights:")
            print(*[f"- {m}" for m in read_only.member], sep="\n")
            print("Reasons:")
            print(*[f"- {reason}\n" for reason in reasons], sep="\n")


def _check_stale_users(group: Entry) -> List[str]:
    reasons = []
    for member in group.member:
        if "Guest" in member:
            reasons.append(f"Group contains a Guest account:\n{member}")

    return reasons


def _search_custom(connection, argparse_arguments) -> None:
    """This function handles the custom command"""
    print(argparse_arguments)
    # Search for the given CN
    connection.search(
        argparse_arguments.base,
        argparse_arguments.query,
        attributes=argparse_arguments.attr,
    )

    if not connection.entries:
        print_error('No entries found.')
        exit(1)

    print(connection.entries)


if __name__ == "__main__":
    # Set up the argparser
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    subparsers = parser.add_subparsers(
        title='commands',
        dest='subparser_name'
    )

    # Add authentication arguments
    g1 = parser.add_argument_group('authentication')
    g1.add_argument(
        '-s',
        '--simple-auth',
        help=SIMPLE_AUTH_HELP,
        action='store_true'
    )
    g1.add_argument('-u', '--username', help=USERNAME_HELP)

    # Add output arguments
    g1 = parser.add_argument_group('output')
    g1.add_argument(
        '-n',
        '--no-format',
        help=NO_FORMAT_HELP,
        action='store_true'
    )

    # Add sub-parser for person search
    p_parser = subparsers.add_parser(
        'person',
        help=PERSON_HELP,
        description=PERSON_DESCRIPTION
    )
    p_parser.add_argument('id', metavar='Search query', type=str, help=SOLIS_HELP)
    p_parser.add_argument('-e', '--email', help=EMAIL_HELP, action='store_true')
    p_parser.add_argument('-a', '--all', help=ALL_HELP, action='store_true')

    # Add sub-parser for group search
    g_parser = subparsers.add_parser(
        'group',
        help=GROUP_HELP,
        description=GROUP_DESCRIPTION
    )
    g_parser.add_argument(
        'id',
        metavar='Search query',
        type=str,
        help=GROUP_QUERY_HELP,
        nargs='?'
    )
    g_parser.add_argument(
        '-r',
        '--raw-search',
        help=GROUP_RAW_HELP,
        action='store_true'
    )

    stale_parser = subparsers.add_parser(
        'stale',
        help=STALE_HELP,
        description=STALE_DESCRIPTION
    )

    custom_parser = subparsers.add_parser(
        'custom',
        help=CUSTOM_HELP,
        description=CUSTOM_DESCRIPTION
    )

    custom_parser.add_argument(
        'query',
        metavar='query',
        type=str,
        help=CUSTOM_QUERY_HELP,
    )

    custom_parser.add_argument(
        'base',
        metavar='base',
        type=str,
        help=CUSTOM_BASE_HELP,
        default='dc=soliscom,dc=uu,dc=nl',
        nargs='?'
    )

    custom_parser.add_argument(
        '--attr',
        type=str,
        help=CUSTOM_ATTR_HELP,
        default=['cn'],
        nargs='*'
    )

    # Get the run config from the argparser
    arguments = parser.parse_args()

    # Setup the server
    server = Server(SERVER_ADDRESS, get_info=ALL, use_ssl=True)

    # Setup the connection
    connection = get_connection(arguments)

    # Force ssl connection active
    connection.start_tls()

    # This regex is used to reduce the groups DN to the first element, and
    # filter out non-UiL groups
    main_regex = re.compile(r'.*?=(.*?GW_UiL.*?),.*')

    # This regex is used to find the ITS-made groups for the new ITS DFS project
    # folders (which follow a different naming convention)
    its_regex = re.compile(r'.*?=(.*?R_FS_Research-GW-Projects.*?),.*')

    # Check which command was given and invoke the corresponding function
    if arguments.subparser_name == 'person':
        _search_user(connection, arguments)
    elif arguments.subparser_name == 'group':
        _search_group(connection, arguments)
    elif arguments.subparser_name == 'stale':
        _search_stale_users_or_groups(connection, arguments)
    elif arguments.subparser_name == 'custom':
        _search_custom(connection, arguments)
    else:
        parser.print_help()
