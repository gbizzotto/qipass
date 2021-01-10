import sys
import os
import json
import getpass
import hashlib
import re
import random
import string
from base64 import b64encode, b64decode
import binascii

#must install
# pip3 install pyperclip
import pyperclip
# pip3 install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# File format
# {
#   "gsalt": "random",
#   "mph2": "SHA256(SHA256(gsalt+master_pwd))",
#   "data": {
#     "SHA256(gsalt+label)":
#     [
#       {"nonce": "random", "login": "AES(master_pwd, nonce)(login)", "password": "AES(master_pwd, nonce)(password)"}
#     ]
#   }
# }

def random_string(size):
	return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(size))
 
def put_in_clipboard(str):
	pyperclip.copy(str)

def get_pw_strength(password):
	strength = 0
	# digits
	if re.search(r'\d', password):
		strength += 1
	if re.search(r'[A-Z]', password):
		strength += 1
	if re.search(r'[a-z]', password):
		strength += 1
	# special chars
	if re.search(r'[^a-zA-Z\d]', password):
		strength += 1
	if len(password) >= 8:
		strength += 1
	if len(password) >= 12:
		strength += 1
	if len(password) >= 16:
		strength += 1

	if any (ord(c)>127 or ord(c)<32 for c in password):
		answer = raw_input("Some characters are exotic, you sure? (y/N) ")
		if answer != 'y':
			sys.exit(0)

	return ["abominable", "weak af", "weak", "meh", "OK, I guess", "good", "strong", "worthy of doom slayer"][strength]

class Vault:
	def __init__(self, filename):
		self.load(filename)

	def __enter__(self):
		return self

	def __exit__(self, type, value, traceback):
		self.reset()

	def reset(self):
		self.mph = ""
		self.mph2 = ""
		self.gsalt = random_string(12)
		self.data = {}

	def load(self, filename):
		self.path = filename
		if os.path.isfile(self.path):
			# prompt for pw first thing, so if the user launches the program and starts typing his master pw right away out of habit, it'll be hidden by getpass
			pw = getpass.getpass("Master password: ")
			with open(filename, 'r') as myfile:
				json_data = myfile.read()
			file_data = json.loads(json_data)
			self.mph2   = file_data['mph2']
			self.data   = file_data['data']
			self.gsalt  = file_data['gsalt']
			self.mph = self.hash_password(self.gsalt + pw)
			if self.mph2 != self.hash_password(self.mph):
				print "    Wrong password."
				sys.exit(0)
			print "    Password OK."
		else:
			answer = raw_input("Create new file? (y/N) ")
			if answer != 'y':
				sys.exit(0)
			self.mph2 = self.create_master_password_hash()
			self.path = filename
			self.gsalt = random_string(12)
			self.data = {}

	def write(self):
		# rename file to avoid data loss if an error occurs during overwriting
		if os.path.isfile(self.path):
			os.rename(self.path, self.path+".old")
		# prepare json
		file_data = {"gsalt": self.gsalt, "mph2": self.mph2, "data": self.data}
		json_data = json.dumps(file_data, default=lambda x: x.__dict__)
		# write
		with open(self.path, 'w') as myfile:
			myfile.write(json_data)

	def has(self, label):
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		return key in self.data.keys()

	def add(self, label, entry):
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data:
			self.data[key] = []
		return self.data[key].append(entry)

	def create_master_password_hash(self):
		pw = getpass.getpass()
		print "    Your password is", get_pw_strength(pw)
		pw2 = getpass.getpass("Confirm: ")
		if pw != pw2:
			print "    Passwords do not match"
			sys.exit(0)
		self.mph = self.hash_password(self.gsalt + pw)
		return self.hash_password(self.mph)

	def hash_password(self, pw):
		return hashlib.sha256(str(pw).encode('utf-8')).hexdigest()

	def cipher(self, data, nonce):
		aes = AES.new(str(self.mph[:32]), AES.MODE_CTR, nonce=str(nonce))
		return binascii.hexlify(aes.encrypt(pad(data, AES.block_size)))

	def decipher(self, data, nonce):
		aes = AES.new(str(self.mph[:32]), AES.MODE_CTR, nonce=str(nonce))
		return unpad(aes.decrypt(binascii.unhexlify(data)), AES.block_size)

	def print_specific(self, label, login):
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data.keys():
			return
		for entry in self.data[key]:
			if self.cipher(login, entry["nonce"]) == entry["login"]:
				choice = 'a'
				while choice not in "sc":
					choice = raw_input("Print password on screen (s) or copy to clipboard (c)? ")
				pw = self.decipher(entry["password"], entry["nonce"])
				if choice == "s":
					sys.stdout.write("    Password: " + pw + "\r")
					sys.stdout.flush()
					raw_input("")
					print "\033[A    Password:", ("*"*max(16,len(pw)))
				else:
					put_in_clipboard(pw)
				return
		print "No entry with that login for", label

	def print_all(self, label):
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data.keys():
			print "    No entries"
			return
		for entry in self.data[key]:
			print "    Login:", self.decipher(entry["login"], entry["nonce"])
			pw = self.decipher(entry["password"], entry["nonce"])
			sys.stdout.write("    Password: " + pw + "\r")
			sys.stdout.flush()
			raw_input("")
			print "\033[A    Password:", ("*"*max(16,len(pw)))

def main(filename):
	try:
		vault = Vault(filename)
		while True:
			label = raw_input("URL/label: ")
			create = False
			if not vault.has(label):
				print "    No entry for this yet."
				create = True
			else:
				print "    There are entrie(s) for this already."
				create = raw_input("Create new? (y/N) ") == 'y'
			if create:
				# new entry
				entry = {}
				nonce = random_string(12)
				entry["nonce"] = nonce
				entry["login"] = vault.cipher(getpass.getpass("Login (optional): "), nonce)
				entry["password"] = vault.cipher(getpass.getpass("Password: "), nonce)
				vault.add(label, entry)
				vault.write()
				print "    Saved."
				continue
			if not vault.has(label):
				print "No entry for this yet."
				continue
			login = getpass.getpass("Care to specify a login? (login/ALL) ")
			if len(login) == 0:
				# let's decipher and show all entries
				vault.print_all(label)
			else:
				vault.print_specific(label, login)
	except KeyboardInterrupt:
		return


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage:", sys.argv[0], "<file>"
		sys.exit(0)
	main(sys.argv[1])