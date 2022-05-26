import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dage/dage.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

void registerPlugin(YubikitOpenPGP interface) {
  AgePlugin.registerPlugin(YubikeyPgpX2559AgePlugin(interface));
}

class YubikeyPgpX2559AgePlugin extends AgePlugin {
  static const publicKeyPrefix = 'age1yubikey1pgp';
  static const tag = 'YUBIX25519';
  final YubikitOpenPGP _interface;

  YubikeyPgpX2559AgePlugin(this._interface);

  static Future<AgeRecipient> generate(YubikitOpenPGP openPGPInterface) async {
    final publicKey = await openPGPInterface.generateECKey(
        KeySlot.encryption, ECCurve.x25519);
    return AgeRecipient(publicKeyPrefix, publicKey);
  }

  static Future<AgeRecipient?> fromCard(YubikitOpenPGP openPGPInterface) async {
    final publicKey = await openPGPInterface.getECPublicKey(KeySlot.encryption);
    if (publicKey == null) {
      return null;
    }
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
  Future<AgeStanza?> parseStanza(List<String> arguments, Uint8List body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    if (arguments.isEmpty || arguments[0] != tag) {
      return null;
    }
    if (arguments.length != 2) {
      throw Exception('Wrong amount of arguments: ${arguments.length}!');
    }
    final ephemeralShare = base64RawDecode(arguments[1]);
    if (ephemeralShare.length != 32) {
      throw Exception('Ephemeral share size is incorrect!');
    }
    if (body.length != 32) {
      throw Exception('Body size is incorrect!');
    }
    return YubikeyX25519Stanza._internal(ephemeralShare, body, _interface);
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) async {
    return null;
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      Uint8List symmetricFileKey, Uint8List salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    return null;
  }
}

class YubikeyX25519Stanza extends AgeStanza {
  static const _info = 'YUBIX25519';
  static const _algorithmTag = YubikeyPgpX2559AgePlugin.tag;
  static final _algorithm = X25519();
  final Uint8List _ephemeralPublicKey;
  final Uint8List _wrappedKey;
  final YubikitOpenPGP _interface;

  YubikeyX25519Stanza._internal(
      this._ephemeralPublicKey, this._wrappedKey, this._interface);

  static Future<YubikeyX25519Stanza> create(YubikitOpenPGP interface,
      Uint8List recipientPublicKey, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    ephemeralKeyPair ??= await _algorithm.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
    final derivedKey =
        await _deriveKey(interface, recipientPublicKey, ephemeralKeyPair);
    final wrappedKey = await _wrap(symmetricFileKey, derivedKey);
    return YubikeyX25519Stanza._internal(
      Uint8List.fromList(ephemeralPublicKey.bytes),
      wrappedKey,
      interface,
    );
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

  static Future<SecretKey> _deriveKey(YubikitOpenPGP interface,
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
      YubikitOpenPGP interface, Uint8List recipientPublicKey) async {
    final sharedSecret = await interface.ecSharedSecret(recipientPublicKey);
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
