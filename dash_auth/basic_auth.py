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
        if username == 'zuser1':
            bind_path = f'cn={username},ou=z Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local'
            user_query = f'(&(objectClass=*)(member=cn={username},ou=z Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local))'
        else:
            bind_path = f'cn={username},ou=Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local'
            user_query = f'(&(objectClass=*)(member=cn={username},ou=Users,ou=USERS,ou=GROUP,dc=COSMO,dc=local))'

        #Verifica credenziali utenza (utenza test: zuser1 Cosmo2023)
        try:
            conn.simple_bind_s(
                bind_path, password
            )
            bind = True
        except Exception as e:
            print('Impossibile effettuare il bind', e)
            bind = False
        #Ricerca utenza nel gruppo di sicurezza
        try:
            user_in_group_search = conn.search_s(
                'cn=LAI-P-CrossNova,ou=CrossNova,ou=Prod Apps,ou=Security Group,ou=CSM - Cosmo Spa,ou=EU - Lainate,ou=SITES,ou=GROUP,dc=COSMO,dc=LOCAL', 
                ldap.SCOPE_SUBTREE, 
                user_query
            )
            if user_in_group_search:
                user_in_group = True
            else:
                user_in_group = False
        except Exception as e:
            print('Impossibile effettuare la ricerca nel gruppo di sicurezza ', e)
            user_in_group = False

        conn.unbind_s()
        if bind and user_in_group:
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
