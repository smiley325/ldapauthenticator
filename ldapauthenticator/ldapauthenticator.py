import ldap3
import re
import sys
import os

from jupyterhub.auth import Authenticator
from tornado import gen
from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from tornado.process import Subprocess
from traitlets import Unicode, Int, Bool, Union, List


class LDAPAuthenticator(Authenticator):
    server_address = Unicode(
        config=True,
        help='Address of LDAP server to contact'
    )
    server_port = Int(
        config=True,
        help='Port on which to contact LDAP server',
    )

    def _server_port_default(self):
        if self.use_ssl:
            return 636  # default SSL port for LDAP
        else:
            return 389  # default plaintext port for LDAP

    use_ssl = Bool(
        True,
        config=True,
        help='Use SSL to encrypt connection to LDAP server'
    )

    bind_dn_template = Unicode(
        config=True,
        help="""
        Template from which to construct the full dn
        when authenticating to LDAP. {username} is replaced
        with the actual username.

        Example:

            uid={username},ou=people,dc=wikimedia,dc=org
        """
    )


    allowed_groups = List(
        config=True,
        help="List of LDAP Group DNs whose members are allowed access"
    )

    valid_username_regex = Unicode(
        r'^[a-z][.a-z0-9_-]*$',
        config=True,
        help="""Regex to use to validate usernames before sending to LDAP

        Also acts as a security measure to prevent LDAP injection. If you
        are customizing this, be careful to ensure that attempts to do LDAP
        injection are rejected by your customization
        """
    )

    lookup_dn = Bool(
        False,
        config=True,
        help='Look up the user\'s DN based on an attribute'
    )

    user_search_base = Unicode(
        config=True,
        help="""Base for looking up user accounts in the directory.

        Example:

            ou=people,dc=wikimedia,dc=org
        """
    )

    user_attribute = Unicode(
        config=True,
        help="""LDAP attribute that stores the user's username.

        For most LDAP servers, this is uid.  For Active Directory, it is
        sAMAccountName.
        """
    )

    @gen.coroutine
    def relog_stderr(self, stderr):
        """
        Shamelessly pawned from https://github.com/jupyterhub/sudospawner/blob/master/sudospawner/spawner.py
        """
        while not stderr.closed():
            try:
                line = yield stderr.read_until(b'\n')
            except StreamClosedError:
                return
            else:
                # TODO: log instead of write to stderr directly?
                # If we do that, will get huge double-prefix messages:
                # [I date JupyterHub] [W date SingleUser] msg...
                sys.stderr.write(line.decode('utf8', 'replace'))

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """
        Shamelessly pawned from https://github.com/jupyterhub/sudospawner/blob/master/sudospawner/spawner.py
        """
        # Add user to jupyterhub group
        cmd = ['sudo', '-n', 'usermod', '-a', '-G', 'jupyterhub', user.name]
        self.log.warn('Running command %s' % ' '.join(cmd))

        p = Subprocess(cmd, stdin=Subprocess.STREAM, stdout=Subprocess.STREAM, stderr=Subprocess.STREAM)
        f = self.relog_stderr(p.stderr)
        # hand the stderr future to the IOLoop so it isn't orphaned,
        # even though we aren't going to wait for it
        IOLoop.current().add_callback(lambda : f)

        p.stdin.close()
        data = yield p.stdout.read_until_close()

        # Add user to jupyterhub group
        if os.path.exists('/home/' + user.name):
            self.log.warn("Home directory for %s already exists, continuing..." % user.name)
        else:
            self.log.warn("Home directory does NOT exist for %s, creating now..." % user.name)
            cmd = ['sudo', '-n', 'mkhomedir_helper', user.name]
            self.log.warn('Running command %s' % ' '.join(cmd))

            p = Subprocess(cmd, stdin=Subprocess.STREAM, stdout=Subprocess.STREAM, stderr=Subprocess.STREAM)
            f = self.relog_stderr(p.stderr)
            # hand the stderr future to the IOLoop so it isn't orphaned,
            # even though we aren't going to wait for it
            IOLoop.current().add_callback(lambda : f)

            p.stdin.close()
            data = yield p.stdout.read_until_close()

    @gen.coroutine
    def authenticate(self, handler, data):
        username = data['username']
        password = data['password']

        # Protect against invalid usernames as well as LDAP injection attacks
        if not re.match(self.valid_username_regex, username):
            self.log.warn('Invalid username')
            return None

        # No empty passwords!
        if password is None or password.strip() == '':
            self.log.warn('Empty password')
            return None

        userdn = self.bind_dn_template.format(username=username)

        server = ldap3.Server(
            self.server_address,
            port=self.server_port,
            use_ssl=self.use_ssl
        )
        conn = ldap3.Connection(server, user=userdn, password=password)

        if conn.bind():
            if self.allowed_groups:
                if self.lookup_dn:
                    # In some cases, like AD, we don't bind with the DN, and need to discover it.
                    conn.search(
                        search_base=self.user_search_base,
                        search_scope=ldap3.SUBTREE,
                        search_filter='({userattr}={username})'.format(
                            userattr=self.user_attribute,
                            username=username
                        ),
                        attributes=[self.user_attribute]
                    )

                    if len(conn.response) == 0:
                        self.log.warn('User with {userattr}={username} not found in directory'.format(
                            userattr=self.user_attribute, username=username))
                        return None
                    userdn = conn.response[0]['dn']

                for group in self.allowed_groups:
                    if conn.search(
                        group,
                        search_scope=ldap3.BASE,
                        search_filter='(member={userdn})'.format(userdn=userdn),
                        attributes=['member']
                    ):
                        return username
                # If we reach here, then none of the groups matched
                self.log.warn('User {username} not in any of the allowed groups'.format(
                    username=userdn
                ))
                return None
            else:
                return username
        else:
            self.log.warn('Invalid password for user {username}'.format(
                username=userdn,
            ))
            return None
