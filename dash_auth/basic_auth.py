from .auth import Auth
import base64
import flask
import ldap


class BasicAuth(Auth):
    def __init__(self, app, username_password_list):
        Auth.__init__(self, app)
        self._users = (
            username_password_list
            if isinstance(username_password_list, dict)
            else {k: v for k, v in username_password_list}
        )

    def is_authorized(self):
        header = flask.request.headers.get('Authorization', None)
        if not header:
            return False
        username_password = base64.b64decode(header.split('Basic ')[1])
        username_password_utf8 = username_password.decode('utf-8')
        username, password = username_password_utf8.split(':', 1)
        conn = ldap.initialize('ldap://192.168.10.25')
        #Utenza Crossnection: zuser1 Cosmo2023
        try:
            conn.simple_bind_s(
                f'cn={username},ou=z Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local', password
            )
            bind_cross = True
        except:
            bind_cross = False
        #Utenza Cosmo
        try:
            conn.simple_bind_s(
                f'cn={username},ou=Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local', password
            )
            bind_cosmo = True
        except:
            bind_cosmo = False
        #Ricerca utenza Crossnection nel gruppo di sicurezza
        try:
            cross_in_group = conn.search_s(
                'cn=LAI-P-CrossNova,ou=CrossNova,ou=Prod Apps,ou=Security Group,ou=CSM - Cosmo Spa,ou=EU - Lainate,ou=SITES,ou=GROUP,dc=COSMO,dc=LOCAL', 
                ldap.SCOPE_SUBTREE, 
                f'(&(objectClass=*)(member=cn={username},ou=z Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local))'
            )
        except:
            cross_in_group = False
        #Ricerca utenza Cosmo nel gruppo di sicurezza
        try:
            cosmo_in_group = conn.search_s(
                'cn=LAI-P-CrossNova,ou=CrossNova,ou=Prod Apps,ou=Security Group,ou=CSM - Cosmo Spa,ou=EU - Lainate,ou=SITES,ou=GROUP,dc=COSMO,dc=LOCAL', 
                ldap.SCOPE_SUBTREE, 
                f'(&(objectClass=*)(member=cn={username},ou=Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local))'
            )
        except:
            cosmo_in_group = False
        conn.unbind_s()
        if (bind_cross and cross_in_group) or (bind_cosmo and cosmo_in_group):
            return True
        else:
            return False

    def login_request(self):
        return flask.Response(
            'Login Required',
            headers={'WWW-Authenticate': 'Basic realm="User Visible Realm"'},
            status=401
        )

    def auth_wrapper(self, f):
        def wrap(*args, **kwargs):
            if not self.is_authorized():
                return flask.Response(status=403)

            response = f(*args, **kwargs)
            return response
        return wrap

    def index_auth_wrapper(self, original_index):
        def wrap(*args, **kwargs):
            if self.is_authorized():
                return original_index(*args, **kwargs)
            else:
                return self.login_request()
        return wrap
