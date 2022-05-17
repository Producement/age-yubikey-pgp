import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../util.dart';
import 'keypair.dart';
import 'plugin.dart';
import 'stanza.dart';

class X25519AgePlugin extends AgePlugin {
  static const publicKeyPrefix = 'age';
  static const privateKeyPrefix = 'AGE-SECRET-KEY-';

  @override
  AgeStanza? parseStanza(List<String> arguments, Uint8List body) {
    if (arguments[0] != 'X25519') {
      return null;
    }
    return X25519AgeStanza._(base64RawDecode(arguments[1]), body);
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeKeypair recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    if (recipient.publicKeyPrefix != publicKeyPrefix) {
      return null;
    }
    return X25519AgeStanza.create(
        recipient.publicKeyBytes, symmetricFileKey, ephemeralKeyPair);
  }
}

class X25519Keypair extends AgeKeypair {
  X25519Keypair(Uint8List? privateKey, Uint8List publicKey)
      : super(privateKey, X25519AgePlugin.privateKeyPrefix, publicKey,
            X25519AgePlugin.publicKeyPrefix);
}

class X25519AgeStanza extends AgeStanza {
  static const _info = 'age-encryption.org/v1/X25519';
  static const _algorithmTag = 'X25519';
  static final _algorithm = X25519();
  final Uint8List _ephemeralPublicKey;
  final Uint8List _wrappedKey;

  X25519AgeStanza._(this._ephemeralPublicKey, this._wrappedKey) : super();

  static Future<X25519AgeStanza> create(
      Uint8List recipientPublicKey, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    ephemeralKeyPair ??= await _algorithm.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
    final derivedKey = await _deriveKey(recipientPublicKey, ephemeralKeyPair);
    final wrappedKey = await _wrap(symmetricFileKey, derivedKey);
    return X25519AgeStanza._(
        Uint8List.fromList(ephemeralPublicKey.bytes), wrappedKey);
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

  static Future<SecretKey> _deriveKey(
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

  static Future<SecretKey> _sharedSecret(
      Uint8List recipientPublicKey, SimpleKeyPair ephemeralKeypair) async {
    final remotePublicKey =
        SimplePublicKey(recipientPublicKey, type: KeyPairType.x25519);
    var sharedSecret = await _algorithm.sharedSecretKey(
        keyPair: ephemeralKeypair, remotePublicKey: remotePublicKey);
    return sharedSecret;
  }

  @override
  Future<Uint8List> decryptedFileKey(AgeKeypair recipient) async {
    final keyPair = SimpleKeyPairData(recipient.privateKeyBytes!,
        publicKey:
            SimplePublicKey(recipient.publicKeyBytes, type: KeyPairType.x25519),
        type: KeyPairType.x25519);
    final ephemeralPublicKey =
        SimplePublicKey(_ephemeralPublicKey, type: KeyPairType.x25519);
    final sharedSecret = await _algorithm.sharedSecretKey(
        keyPair: keyPair, remotePublicKey: ephemeralPublicKey);

    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final salt = ephemeralPublicKey.bytes + recipient.publicKeyBytes;
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
