import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../util.dart';

class AgeStanza {
  static const _info = "age-encryption.org/v1/X25519";
  static const _algorithmTag = "X25519";
  static final _algorithm = X25519();
  final Uint8List _recipientPublicKey;
  final SimpleKeyPair _ephemeralKeyPair;

  AgeStanza._(this._recipientPublicKey, this._ephemeralKeyPair);

  static Future<AgeStanza> create(Uint8List recipientPublicKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    return AgeStanza._(
        recipientPublicKey, ephemeralKeyPair ?? await _algorithm.newKeyPair());
  }

  Future<String> serialize(Uint8List symmetricFileKey) async {
    final publicKey = await _ephemeralKeyPair.extractPublicKey();
    final derivedKey = await _deriveKey(_recipientPublicKey, _ephemeralKeyPair);

    final header = "-> $_algorithmTag ${base64Raw(publicKey.bytes)}";
    final body = base64Raw(await _wrap(symmetricFileKey, derivedKey));
    return "${wrapAtPosition(header)}\n${wrapAtPosition(body)}";
  }

  Future<List<int>> _wrap(
      Uint8List symmetricFileKey, SecretKey derivedKey) async {
    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final body = await wrappingAlgorithm.encrypt(symmetricFileKey,
        secretKey: derivedKey, nonce: List.generate(12, (index) => 0x00));
    return body.concatenation(nonce: false);
  }

  Future<SecretKey> _deriveKey(
      Uint8List recipientPublicKey, SimpleKeyPair keyPair) async {
    final sharedSecret = await _sharedSecret(recipientPublicKey, keyPair);
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final salt = (await keyPair.extractPublicKey()).bytes + recipientPublicKey;
    final derivedKey = await hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: _info.codeUnits, nonce: salt);
    return derivedKey;
  }

  Future<SecretKey> _sharedSecret(
      Uint8List recipientPublicKey, SimpleKeyPair ephemeralKeypair) async {
    final remotePublicKey =
        SimplePublicKey(recipientPublicKey, type: KeyPairType.x25519);
    var sharedSecret = await _algorithm.sharedSecretKey(
        keyPair: ephemeralKeypair, remotePublicKey: remotePublicKey);
    return sharedSecret;
  }
}