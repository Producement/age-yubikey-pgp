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

  @override
  Future<AgeStanza?> createStanza(
      AgeKeypair recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    if (recipient.publicKeyPrefix != publicKeyPrefix) {
      return null;
    }
    return YubikeyX25519Stanza.create(_interface, recipient.publicKeyBytes,
        symmetricFileKey, ephemeralKeyPair);
  }

  @override
  AgeStanza? parseStanza(List<String> arguments, Uint8List body) {
    if (arguments[0] != tag) {
      return null;
    }
    return YubikeyX25519Stanza._(base64RawDecode(arguments[1]), body);
  }
}

class YubikeyX25519Keypair extends AgeKeypair {
  YubikeyX25519Keypair(Uint8List publicKey)
      : super(null, null, publicKey, YubikeyPgpAgePlugin.publicKeyPrefix);

  static Future<YubikeyX25519Keypair> generate(
      YubikeySmartCardInterface smartCardInterface) async {
    final publicKey = await smartCardInterface.generateKeyPair('12345678');
    return YubikeyX25519Keypair(publicKey);
  }

  static Future<YubikeyX25519Keypair> fromCard(
      YubikeySmartCardInterface smartCardInterface) async {
    final publicKey = await smartCardInterface.getPublicKey();
    return YubikeyX25519Keypair(publicKey);
  }
}

class YubikeyX25519Stanza extends AgeStanza {
  static const _info = 'age-encryption.org/v1/YUBIX25519';
  static const _algorithmTag = YubikeyPgpAgePlugin.tag;
  static final _algorithm = X25519();
  final Uint8List _ephemeralPublicKey;
  final Uint8List _wrappedKey;

  YubikeyX25519Stanza._(this._ephemeralPublicKey, this._wrappedKey) : super();

  static Future<YubikeyX25519Stanza> create(YubikeySmartCardInterface interface,
      Uint8List recipientPublicKey, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    ephemeralKeyPair ??= await _algorithm.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
    final derivedKey =
        await _deriveKey(interface, recipientPublicKey, ephemeralKeyPair);
    final wrappedKey = await _wrap(symmetricFileKey, derivedKey);
    return YubikeyX25519Stanza._(
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

  static Future<SecretKey> _deriveKey(YubikeySmartCardInterface interface,
      Uint8List recipientPublicKey, SimpleKeyPair keyPair) async {
    final sharedSecret =
        await _sharedSecret(interface, recipientPublicKey, keyPair);
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final salt = (await keyPair.extractPublicKey()).bytes + recipientPublicKey;
    final derivedKey = await hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: _info.codeUnits, nonce: salt);
    return derivedKey;
  }

  static Future<SecretKey> _sharedSecret(YubikeySmartCardInterface interface,
      Uint8List recipientPublicKey, SimpleKeyPair ephemeralKeypair) async {
    final sharedSecret =
        await interface.calculateSharedSecret(recipientPublicKey, '12345678');
    return SecretKey(sharedSecret);
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
