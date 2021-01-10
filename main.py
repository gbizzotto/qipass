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
import copy
import time

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

if sys.version_info[0] < 3:
	def monotonic_time():
		return time.time()
else:
	def monotonic_time():
		return time.clock_gettime(time.CLOCK_MONOTONIC_RAW)

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

def hash_password(pw):
	return hashlib.sha256(str(pw).encode('utf-8')).hexdigest()

class Pin:
	timeout = 30 # seconds
	def __init__(self):
		self.salt = random_string(12)
		self.hashed_pin = hash_password(self.salt + getpass.getpass("Create session pin: "))
		self.checkpoint = monotonic_time()
	def check(self):
		if monotonic_time() - self.checkpoint > Pin.timeout and self.hashed_pin != hash_password(self.salt + getpass.getpass("Pin: ")):
			print "    Wrong pin."
			sys.exit(0)
		self.checkpoint = monotonic_time()

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
			self.mph = hash_password(self.gsalt + pw)
			if self.mph2 != hash_password(self.mph):
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
		self.pin = Pin()

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

	def has_label(self, label):
		self.pin.check()
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		return key in self.data.keys()

	def has_login(self, label, login):
		self.pin.check()
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data.keys():
			print "    No entries for", label
			return
		for entry in self.data[key]:
			if self.cipher(login, entry["nonce"]) == entry["login"]:
				return True
		print "    No entry with that login for", label
		return False

	def add(self, label, entry):
		self.pin.check()
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
		self.mph = hash_password(self.gsalt + pw)
		return hash_password(self.mph)

	def cipher(self, data, nonce):
		self.pin.check()
		aes = AES.new(str(self.mph[:32]), AES.MODE_CTR, nonce=str(nonce))
		return binascii.hexlify(aes.encrypt(pad(data, AES.block_size)))

	def decipher(self, data, nonce):
		self.pin.check()
		aes = AES.new(str(self.mph[:32]), AES.MODE_CTR, nonce=str(nonce))
		return unpad(aes.decrypt(binascii.unhexlify(data)), AES.block_size)

	def print_specific(self, label, login):
		self.pin.check()
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data.keys():
			print "    No entries for", label
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
		print "    No entry with that login for", label

	def print_all(self, label):
		self.pin.check()
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data.keys():
			print "    No entries for", label
			return
		for entry in self.data[key]:
			print "    Login:", self.decipher(entry["login"], entry["nonce"])
			pw = self.decipher(entry["password"], entry["nonce"])
			sys.stdout.write("    Password: " + pw + "\r")
			sys.stdout.flush()
			raw_input("")
			print "\033[A    Password:", ("*"*max(16,len(pw)))

	def delete(self, label, login):
		self.pin.check()
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data.keys():
			print "    No entries for", label
			return
		for entry in self.data[key]:
			if self.cipher(login, entry["nonce"]) == entry["login"]:
				self.data[key].remove(entry)
				if len(self.data[key]) == 0:
					del self.data[key]
				return True
		print "    No entry with that login for", label
		return False

	def update(self, label, login, pw):
		self.pin.check()
		key = hashlib.sha256(str(self.gsalt + label).encode('utf-8')).hexdigest()
		if key not in self.data.keys():
			print "    No entries for", label
			return
		for entry in self.data[key]:
			if self.cipher(login, entry["nonce"]) == entry["login"]:
				entry["password"] = self.cipher(pw, entry["nonce"])
				return True
		print "    No entry with that login for", label
		return False


def main(filename):
	try:
		vault = Vault(filename)
		while True:
			label = raw_input("URL/label: ")
			action = None
			if not vault.has_label(label):
				print "    No entry for this yet, let's create one."
				action = 'c'
			else:
				print "    There are entrie(s) for this already."
				action = raw_input("Create/View/Update/Delete/NoAction? (c/v/u/d/N) ")
			if action == 'c':
				# new entry
				entry = {}
				nonce = random_string(12)
				entry["nonce"] = nonce
				entry["login"] = vault.cipher(getpass.getpass("Login (optional): "), nonce)
				entry["password"] = vault.cipher(getpass.getpass("Password: "), nonce)
				confirm_pw = vault.cipher(getpass.getpass("Confirm: "), nonce)
				if confirm_pw != entry["password"]:
					print "    Passwords differ."
					continue
				vault.add(label, entry)
				vault.write()
				print "    Saved."
				continue
			elif action == 'v':
				login = getpass.getpass("Care to specify a login? (login/ALL) ")
				if len(login) == 0:
					# let's decipher and show all entries
					vault.print_all(label)
				else:
					vault.print_specific(label, login)
			elif action == 'd':
				login = getpass.getpass("Login do delete: ")
				if len(login) == 0:
					confirm = raw_input("Delete entry for '" + label + "' with empty login? (y/N) ")
					if confirm != 'y':
						continue
				vault_backup = copy.deepcopy(vault)
				if vault.delete(label, login) == False:
					continue
				print "    One entry for '" + label + "' was deleted."
				confirm = raw_input("Commit vault to file? (y/N) ")
				if confirm != 'y':
					del vault
					vault = vault_backup
					print "    Cancelled."
					continue
				del vault_backup
				vault.write()
				print "    Saved."
			elif action == 'u':
				login = getpass.getpass("Login do update: ")
				if not vault.has_login(label, login):
					continue
				pw = getpass.getpass("New password: ")
				confirm_pw = getpass.getpass("Confirm: ")
				if confirm_pw != pw:
					print "    Passwords differ."
					continue
				vault_backup = copy.deepcopy(vault)
				if vault.update(label, login, pw) == False:
					continue
				print "    One entry for '" + label + "' was updated."
				confirm = raw_input("Commit vault to file? (y/N) ")
				if confirm != 'y':
					del vault
					vault = vault_backup
					print "    Cancelled."
					continue
				del vault_backup
				vault.write()
				print "    Saved."
				


	except KeyboardInterrupt:
		return


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage:", sys.argv[0], "<file>"
		sys.exit(0)
	main(sys.argv[1])