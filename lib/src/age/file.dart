import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/header.dart';
import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:age_yubikey_pgp/src/util.dart';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';

class AgeFile {
  final Uint8List _content;

  AgeFile(this._content);

  Future<Uint8List> encrypt(List<Uint8List> recipients,
      [Uint8List? symmetricFileKey,
      SimpleKeyPair? keyPair,
      Uint8List? nonce]) async {
    symmetricFileKey ??=
        Uint8List.fromList(SecretKeyData.random(length: 16).bytes);
    final stanzas =
        await Future.wait<AgeStanza>(recipients.map((recipient) async {
      return AgeStanza.create(symmetricFileKey!, recipient, keyPair);
    }));
    final header = AgeHeader(stanzas, symmetricFileKey);
    return Uint8List.fromList((await header.serialize()) +
        "\n".codeUnits +
        await _payload(symmetricFileKey, nonce));
  }

  Future<Uint8List> _payload(Uint8List symmetricFileKey,
      [Uint8List? nonce]) async {
    nonce ??= Uint8List.fromList(SecretKeyData.random(length: 16).bytes);
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: nonce,
        info: "payload".codeUnits);
    final encryptionAlgorithm = Chacha20.poly1305Aead();
    final chunkedContent = chunk(_content, 64 * 1024);
    final encrypted =
        await Future.wait(chunkedContent.mapIndexed((i, chunk) async {
      final nonceEnd = i == (chunkedContent.length - 1) ? [0x01] : [0x00];
      final secretBox = await encryptionAlgorithm.encrypt(_content,
          nonce: List.generate(11, (index) => 0) + nonceEnd,
          secretKey: payloadKey);
      return secretBox.concatenation(nonce: false);
    }));

    final joinEncrypted = encrypted
        .reduce((value, element) => Uint8List.fromList(value + element));

    final payloadNonce = List.generate(16, (index) => 1);
    return Uint8List.fromList(payloadNonce + joinEncrypted);
  }
}
