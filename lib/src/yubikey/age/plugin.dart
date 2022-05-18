library yubikey_age;

import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/age/plugin.dart';
import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:cryptography/cryptography.dart';

import '../../util.dart';
import '../yubikey_smartcard_interface.dart';

class YubikeyPgpAgePlugin extends AgePlugin {
  static const publicKeyPrefix = 'age1yubikey1pgp';
  static const tag = 'YUBIX25519';
  final YubikeySmartCardInterface _interface;

  YubikeyPgpAgePlugin(this._interface);

  static Future<AgeRecipient> generate(
      YubikeySmartCardInterface smartCardInterface) async {
    final publicKey = await smartCardInterface.generateKeyPair();
    return AgeRecipient(publicKeyPrefix, publicKey);
  }

  static Future<AgeRecipient> fromCard(
      YubikeySmartCardInterface smartCardInterface) async {
    final publicKey = await smartCardInterface.getPublicKey();
    return AgeRecipient(publicKeyPrefix, publicKey);
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    if (recipient.prefix != publicKeyPrefix) {
      return null;
    }
    return YubikeyX25519Stanza.create(
        _interface, recipient.bytes, symmetricFileKey, ephemeralKeyPair);
  }

  @override
  AgeStanza? parseStanza(List<String> arguments, Uint8List body) {
    if (arguments[0] != tag) {
      return null;
    }
    return YubikeyX25519Stanza._internal(
        base64RawDecode(arguments[1]), body, _interface);
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) async {
    return null;
  }
}

class YubikeyX25519Stanza extends AgeStanza {
  static const _info = 'age-encryption.org/v1/YUBIX25519';
  static const _algorithmTag = YubikeyPgpAgePlugin.tag;
  static final _algorithm = X25519();
  final Uint8List _ephemeralPublicKey;
  final Uint8List _wrappedKey;
  final YubikeySmartCardInterface _interface;

  YubikeyX25519Stanza._internal(
      this._ephemeralPublicKey, this._wrappedKey, this._interface);

  static Future<YubikeyX25519Stanza> create(YubikeySmartCardInterface interface,
      Uint8List recipientPublicKey, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    ephemeralKeyPair ??= await _algorithm.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
    final derivedKey =
        await _deriveKey(interface, recipientPublicKey, ephemeralKeyPair);
    final wrappedKey = await _wrap(symmetricFileKey, derivedKey);
    return YubikeyX25519Stanza._internal(
        Uint8List.fromList(ephemeralPublicKey.bytes), wrappedKey, interface);
  }

  @override
  Future<String> serialize() async {
    final header = '-> $_algorithmTag ${base64RawEncode(_ephemeralPublicKey)}';
    final body = base64RawEncode(_wrappedKey);
    return '${wrapAtPosition(header)}\n${wrapAtPosition(body)}';
  }

  static Future<Uint8List> _wrap(
      Uint8List symmetricFileKey, SecretKey derivedKey) async {
    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final body = await wrappingAlgorithm.encrypt(symmetricFileKey,
        secretKey: derivedKey, nonce: List.generate(12, (index) => 0x00));
    return body.concatenation(nonce: false);
  }

  static Future<SecretKey> _deriveKey(YubikeySmartCardInterface interface,
      Uint8List recipientPublicKey, SimpleKeyPair keyPair) async {
    final sharedSecret = await _sharedSecret(interface, recipientPublicKey);
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final salt = (await keyPair.extractPublicKey()).bytes + recipientPublicKey;
    final derivedKey = await hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: _info.codeUnits, nonce: salt);
    return derivedKey;
  }

  static Future<SecretKey> _sharedSecret(
      YubikeySmartCardInterface interface, Uint8List recipientPublicKey) async {
    final sharedSecret =
        await interface.calculateSharedSecret(recipientPublicKey);
    return SecretKey(sharedSecret);
  }

  @override
  Future<Uint8List> decryptedFileKey(AgeKeyPair keyPair) async {
    final ephemeralPublicKey =
        SimplePublicKey(_ephemeralPublicKey, type: KeyPairType.x25519);
    final sharedSecret =
        await _sharedSecret(_interface, keyPair.recipientBytes);

    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final salt = ephemeralPublicKey.bytes + keyPair.recipientBytes;
    final derivedKey = await hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: _info.codeUnits, nonce: salt);
    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final secretBox = SecretBox.fromConcatenation(
        List.generate(12, (index) => 0x00) + _wrappedKey,
        macLength: 16,
        nonceLength: 12);
    return Uint8List.fromList(
        await wrappingAlgorithm.decrypt(secretBox, secretKey: derivedKey));
  }
}
