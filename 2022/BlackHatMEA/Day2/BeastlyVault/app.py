#!/usr/local/bin/python
#
# Polymero
#

# Imports
from flask import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os, time

# Local imports
FLAG = os.environ.get('FLAG', 'flag{spl4t_th3m_bugs}')

# Global parameters
USER_ALP = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"



#------------------------------------------------------------------------------------------------------------------
# Classes
#------------------------------------------------------------------------------------------------------------------ 
class json:
    def loads(packet):
        jstr = packet[packet.index(123)+1:packet.index(125)].split(b',')
        jlst = [[j.strip(b' "').decode() for j in i.split(b':')] for i in jstr]
        jobj = {}
        for key, value in jlst:
            if key in jobj:
                raise ValueError()
            else:
                jobj[key] = value
        return jobj

    def dumps(packet):
        jstr = '{'
        for key in packet.keys():
            value = packet[key]
            if type(value) in [int,dict,list,float]:
                jstr += '"{}": {}, '.format(key, value)
            else:
                jstr += '"{}": "{}", '.format(key, value)
        jstr = jstr[:-2]
        jstr += '}'
        return jstr

class Crypto:
    def __init__(self):
        self.key = os.urandom(32)

    def encrypt(self, msg):
        pdm = pad(msg, 16)
        riv = os.urandom(16)
        aes = AES.new(key=self.key, mode=AES.MODE_CBC, iv=riv)
        cip = riv + aes.encrypt(pdm)
        return cip

    def decrypt(self, cip):
        riv, cip = cip[:16], cip[16:]
        aes = AES.new(key=self.key, mode=AES.MODE_CBC, iv=riv)
        pdm = aes.decrypt(cip)
        msg = unpad(pdm, 16)
        return msg

class Vault:
    def __init__(self):
        self.crypto = Crypto()
        self.access_code = int.from_bytes(os.urandom(24),'big')
        self.contents = FLAG

    def access(self, token):
        try:
            token = self.crypto.decrypt(bytes.fromhex(token))
            token = json.loads(token)
        except:
            return 'Invalid or broken token.', None
        try:
            rule1 = token["user"] == "admin"
            rule2 = int(token["iat"]) < 1637629549
            rule3 = "REMOTE__Vault.access" in token["priv"]
            rule4 = token["code"] == str(self.access_code)
            if all([rule1, rule2, rule3, rule4]):
                return None, {"user": token["user"], "cont": vault.contents}
            else:
                return None, {"user": token["user"], "cont": 'You do not have the required permissions to access the Vault.'}
        except:
            return 'Invalid or broken token.', None

    def create_token(self, user):
        user = ''.join([i for i in list(user) if i in USER_ALP])
        token = {
            "user" : user,
            "iat"  : int(time.time()),
            "priv" : [],
            "code" : str(self.access_code)
        }
        token = self.crypto.encrypt(json.dumps(token).encode())
        return token.hex()



#------------------------------------------------------------------------------------------------------------------
# Flask Web App
#------------------------------------------------------------------------------------------------------------------ 
app   = Flask(__name__)
vault = Vault()

app.secret_key = vault.crypto.key


@app.route('/', methods=['GET'])
def index():
    try:
        acto = request.cookies.get('access_token')
        if acto is None: 
            raise ValueError()
        error, resp = vault.access(acto)
        if error:
            flash('ERROR :: {}'.format(error), 'error')
            return render_template('invalid.html')
        else:
            flash('Token succesfully loaded.', 'success')
            return render_template('vault.html', resp=resp)
    except:
        flash('Lost your token? Contact your local administrator as soon as possible.', 'warning')
        return render_template('missing.html')


@app.route('/register/<username>/')
def register(username):
    if 'admin' in username.lower():
        return redirect('/')
    else:
        acto = vault.create_token(username)
        resp = make_response(redirect('/'))
        resp.set_cookie('access_token', acto)
        return resp


def check_dev_priv(func):
    try:
        acto = request.cookies.get('access_token')
        if acto is None:
            return False
        token = vault.crypto.decrypt(bytes.fromhex(acto))
        token = json.loads(token)
        if func not in token["priv"]:
            raise ValueError()
        else:
            return True
    except:
        return False

@app.route('/dev/test/gcm_encrypt/<jobj>/')
def gcm_encrypt(jobj):
    try:
        # Check developer privilage
        assert check_dev_priv("gcm_encrypt")
        jobj = json.loads(jobj.encode())
        nonce, msg = [bytes.fromhex(i) for i in [jobj["nonce"], jobj["msg"]]]
        aes = AES.new(key=vault.crypto.key, mode=AES.MODE_GCM, nonce=nonce)
        cip, tag = aes.encrypt_and_digest(msg)
        return json.dumps({"cip": cip.hex(), "tag": tag.hex()})
    except:
        flash('ERROR :: You do not have the required privilages.', 'error')
        return render_template('invalid.html')



#------------------------------------------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------------------------------------------ 
if __name__ == '__main__':
    app.run(host='0.0.0.0')
