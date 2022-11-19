#!/usr/local/bin/python
#
#

# Imports
from flask import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os, json

# Local import
FLAG = os.environ.get('FLAG', 'flag{spl4t_th3m_bugs}')

# Global parameters
ALLOWED = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'


# Classes
class Crypto:
	def __init__(self, key):
		self.key = key

	def encrypt(self, msg):
		pdm = pad(msg, 16)
		riv = os.urandom(16)
		aes = AES.new(self.key, AES.MODE_CBC, riv)
		cip = riv + aes.encrypt(pdm)
		return cip

	def decrypt(self, cip):
		riv, cip = cip[:16], cip[16:]
		aes = AES.new(self.key, AES.MODE_CBC, riv)
		pdm = aes.decrypt(cip)
		msg = unpad(pdm, 16)
		return msg

	def remove_illegal_chars(self, token):
		il = token.index(b': "') + 3
		ir = il + token[il:].index(b'"')
		return token[:il] + bytes(i for i in token[il:ir] if i in ALLOWED) + token[ir:]

	def gen_token(self, username, admin=False):
		raw = {
				'username' : username, 
				'admin'	   : admin
			  }
		tok = json.dumps(raw).encode()
		enc = self.encrypt(tok)
		return enc.hex()

	def validate_token(self, enc):
		try:
			tok = self.remove_illegal_chars(self.decrypt(enc))
			raw = json.loads(tok)
			return raw['username'], raw['admin']
		except:
			raise ValueError()


# Webpage
app = Flask(__name__)
app.secret_key = os.urandom(32)
crypto = Crypto(app.secret_key)

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login/<username>')
def login(username):
	token = request.cookies.get('token')
	if token is not None:
		try:
			user, admin = crypto.validate_token(bytes.fromhex(token))
			assert username == user
			flash('Successfully logged in ' + user + '.', 'success')
			if admin is True:
				return render_template('flag.html', flag=FLAG)
			else:
				return render_template('flag.html', flag='Nothing to be found here.')
		except:
			flash('Invalid login token.', 'error')
			return redirect('/')
	else:
		flash('Please register or load your login token before logging in.', 'error')
		return redirect('/')

@app.route('/register/<username>')
def register(username):
	if username:
		try:
			cookie = crypto.gen_token(username, admin=False)
			resp = make_response(redirect('/'))
			resp.set_cookie('token', cookie)
			flash('Successfully registered ' + username + '.', 'success')
			return resp
		except:
			flash('Oop- Something went wrong.', 'error')
			return redirect('/')
	else:
		flash('Please enter a username.', 'error')
		return redirect('/')

# Main
if __name__ == '__main__':
	app.run(host='0.0.0.0')