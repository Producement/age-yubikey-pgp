# Yubikey PGP Age Encryption plugin

Proof of concept [age](http://age-encryption.org/) plugin that uses the PGP application on a Yubikey to encrypt/decrypt files using x25519.

Goal is to fully implement the [age plugin spec](https://github.com/C2SP/C2SP/pull/5), but currently it only integrates with [dage](https://pub.dev/packages/dage) directly.