import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dage/dage.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

import 'key_derivator.dart';
import 'wrapped_key.dart';

class YubikeyX25519Stanza extends AgeStanza {
  static const tag = 'YUBIX25519';
  static final _algorithm = X25519();
  static final KeyDerivator _keyDerivator = KeyDerivator();

  final List<int> _ephemeralPublicKey;
  final WrappedKey _wrappedKey;
  final YubikitOpenPGP _interface;

  const YubikeyX25519Stanza(
      this._ephemeralPublicKey, this._wrappedKey, this._interface);

  static Future<YubikeyX25519Stanza> create(YubikitOpenPGP interface,
      List<int> recipientPublicKey, List<int> symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    ephemeralKeyPair ??= await _algorithm.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
    final sharedSecret =
        await _stanzaSharedSecret(ephemeralKeyPair, recipientPublicKey);
    final derivedKey = await _keyDerivator.derive(
        sharedSecret, recipientPublicKey, ephemeralPublicKey.bytes);
    final wrappedKey = WrappedKey(symmetricFileKey, derivedKey);
    return YubikeyX25519Stanza(
      ephemeralPublicKey.bytes,
      wrappedKey,
      interface,
    );
  }

  @override
  Future<String> serialize() async {
    final header = '-> $tag ${base64RawEncode(_ephemeralPublicKey)}';
    final body = await _wrappedKey.base64;
    return '${wrapAtPosition(header)}\n${wrapAtPosition(body)}';
  }

  static Future<SecretKey> _sharedSecret(
      YubikitOpenPGP interface, List<int> recipientPublicKey) async {
    final sharedSecret =
        await interface.ecSharedSecret(Uint8List.fromList(recipientPublicKey));
    if (sharedSecret.every((element) => element == 0x00)) {
      throw Exception('All shared secret bytes are 0x00!');
    }
    return SecretKey(sharedSecret);
  }

  static Future<SecretKey> _stanzaSharedSecret(
      SimpleKeyPair ephemeralKeyPair, List<int> recipientPublicKey) async {
    final sharedSecretKey = await _algorithm.sharedSecretKey(
        keyPair: ephemeralKeyPair,
        remotePublicKey:
            SimplePublicKey(recipientPublicKey, type: KeyPairType.x25519));
    final sharedSecret = await sharedSecretKey.extractBytes();
    if (sharedSecret.every((element) => element == 0x00)) {
      throw Exception('All shared secret bytes are 0x00!');
    }
    return SecretKey(sharedSecret);
  }

  @override
  Future<Uint8List> decryptedFileKey(AgeKeyPair? keyPair) async {
    if (keyPair == null) {
      throw Exception('Keypair is mandatory!');
    }
    final sharedSecret = await _sharedSecret(_interface, _ephemeralPublicKey);

    final derivedKey = await _keyDerivator.derive(
        sharedSecret, keyPair.recipientBytes, _ephemeralPublicKey);
    return Uint8List.fromList(await _wrappedKey.unwrap(derivedKey));
  }
}
