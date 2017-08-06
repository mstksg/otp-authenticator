# otp-authenticator

Simple tool for keeping track of your one-time pad two-factor authentication
keys; basically a command-line version of the canonical [Google Authenticator
App][gauth].

[gauth]: https://github.com/google/google-authenticator

The library uses GnuPG (through *h-gpgme*) to safely encrypt your secret keys.
The first time you use it, it asks for a fingerprint to use for encryption.
Currently *GnuPG 1.x* has some issues with *h-gpgme* when asking for keys, so
*GPG 2.x* is recommended.  Keys are stored, encrypted, at `~/.otp-auth.vault`
by default.

Instructions are available through `--help`, but the basics are:

```bash
# interactively add a new key
otp-auth add

# interactively add a new key by entering the secret key uri
#   (following the otpauth protocol)
otp-auth add --uri

# view all time-based codes and cached counter-based codes
otp-auth view

# list accounts, do not display codes
otp-auth view --list

# generate a new counter-based code
otp-auth gen ID

# edit the metadata and delete codes
otp-auth edit ID
otp-auth delete ID

# dump all stored data as json (and as yaml)
otp-auth dump
otp-auth dump --yaml
```

You can edit configuration at `~/.otp-auth.yaml`, the basic schema is:

```yaml
fingerprint: ABCDEF12
vault: /home/robert/.otp-auth.vault
```
