# qipass
hardcore command-line local-file password manager in python

### How it does its thing

`qipass` stores logins and passwords ciphered with your master password. It writes everything down in a file (the one you give in as parameter) called `vault` in the code.
It'll also keep a hash of your password to be checked when you open a vault, to be sure deciphering won't give back garbage.

### How to use

```python2 main.py <my_vault_file>```

First thing, the master password. If you're creating a new file, create a password. `qipass` will judge it. And you.

If you're opening an existing file, unlock it with that same master password.

Then `qipass` will ask you what site (or game, or app, whatever, it's all `label` s to it) you want to keep or retrieve a password for.

If you're storing a new password, it'll ask for for a login as well. You may store more than one login per label.

If you're retrieving a password, it'll ask your for an optional login. If none is provided, it'll show you all your credentials for that label. If you give it a login, it'll show you (and whomever is watching) only the password for that label and that login.

### TODO

- See issues
