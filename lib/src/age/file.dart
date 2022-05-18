import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/header.dart';
import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/age/plugin.dart';
import 'package:age_yubikey_pgp/src/age/random.dart';
import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:age_yubikey_pgp/src/util.dart';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';

class AgeFile {
  static final Logger logger = Logger('AgeFile');
  final Uint8List _content;

  AgeFile(this._content);

  Uint8List get content => _content;

  Future<Uint8List> decrypt(List<AgeKeypair> identities) async {
    final headerAndPayload = String.fromCharCodes(_content)
        .split('\n')
        .splitAfter((element) => element.startsWith('---'))
        .toList();
    if (headerAndPayload.length != 2) {
      throw Exception(
          'Something went wrong with parsing: ${headerAndPayload.length}');
    }
    final header = AgeHeader.parse(headerAndPayload[0].join('\n'));
    Uint8List? symmetricFileKey;
    for (var identity in identities) {
      for (var stanza in header.stanzas) {
        try {
          symmetricFileKey = await stanza.decryptedFileKey(identity);
        } catch (e, stacktrace) {
          logger.warning(stacktrace);
          //Ignore
        }
      }
    }
    if (symmetricFileKey == null) {
      throw Exception('Recipient not found');
    }
    await header.checkMac(symmetricFileKey);
    final payload = headerAndPayload[1].join('\n');
    return _decryptPayload(Uint8List.fromList(payload.codeUnits),
        symmetricFileKey: symmetricFileKey);
  }

  static Future<AgeFile> encrypt(Uint8List payload, List<AgeKeypair> recipients,
      {AgeRandom random = const AgeRandom(), SimpleKeyPair? keyPair}) async {
    final symmetricFileKey = random.bytes(16);
    final stanzas =
        await Future.wait<AgeStanza>(recipients.map((recipient) async {
      return AgePlugin.stanzaCreate(recipient, symmetricFileKey, keyPair);
    }));
    final header = await AgeHeader.create(stanzas, symmetricFileKey);
    final payloadNonce = random.bytes(16);
    return AgeFile(Uint8List.fromList((await header.serialize()).codeUnits +
        '\n'.codeUnits +
        await _encryptPayload(payload,
            symmetricFileKey: symmetricFileKey, nonce: payloadNonce)));
  }

  Future<Uint8List> _decryptPayload(Uint8List payload,
      {required Uint8List symmetricFileKey}) async {
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final nonce = payload.sublist(0, 16);
    payload = payload.sublist(16);
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: nonce,
        info: 'payload'.codeUnits);
    final encryptionAlgorithm = Chacha20.poly1305Aead();
    final chunkedContent = chunk(payload, 64 * 1024);
    final decrypted =
        await Future.wait(chunkedContent.mapIndexed((i, chunk) async {
      final nonceEnd = i == (chunkedContent.length - 1) ? [0x01] : [0x00];
      final secretBox = SecretBox.fromConcatenation(
          List.generate(11, (index) => 0) + nonceEnd + chunk,
          nonceLength: 12,
          macLength: 16);
      final decrypted =
          await encryptionAlgorithm.decrypt(secretBox, secretKey: payloadKey);
      return Uint8List.fromList(decrypted);
    }));
    return decrypted
        .reduce((value, element) => Uint8List.fromList(value + element));
  }

  static Future<Uint8List> _encryptPayload(Uint8List payload,
      {required Uint8List symmetricFileKey, required Uint8List nonce}) async {
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: nonce,
        info: 'payload'.codeUnits);
    final encryptionAlgorithm = Chacha20.poly1305Aead();
    final chunkedContent = chunk(payload, 64 * 1024);
    final encrypted =
        await Future.wait(chunkedContent.mapIndexed((i, chunk) async {
      final nonceEnd = i == (chunkedContent.length - 1) ? [0x01] : [0x00];
      final secretBox = await encryptionAlgorithm.encrypt(chunk,
          nonce: List.generate(11, (index) => 0) + nonceEnd,
          secretKey: payloadKey);
      return secretBox.concatenation(nonce: false);
    }));

    final joinEncrypted = encrypted
        .reduce((value, element) => Uint8List.fromList(value + element));
    print(Uint8List.fromList(nonce + joinEncrypted));
    return Uint8List.fromList(nonce + joinEncrypted);
  }
}