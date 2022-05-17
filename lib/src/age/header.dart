import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:age_yubikey_pgp/src/util.dart';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';

class AgeHeader {
  static const _version = 'age-encryption.org/v1';
  final List<AgeStanza> _stanzas;
  final String _mac;

  AgeHeader._(this._stanzas, this._mac);

  List<AgeStanza> get stanzas => _stanzas;

  static Future<AgeHeader> create(
      List<AgeStanza> stanzas, Uint8List symmetricFileKey) async {
    final mac =
        await _calculateMac(await headerWithoutMac(stanzas), symmetricFileKey);
    return AgeHeader._(stanzas, mac);
  }

  static AgeHeader parse(String content) {
    final headerAndPayload = content
        .split('\n')
        .splitAfter((element) => element.startsWith('---'))
        .toList();
    final headerLines = headerAndPayload[0];
    final versionLine = headerLines[0];
    if (versionLine != _version) {
      throw Exception('Unsupported version: $versionLine');
    }
    final stanzaContent = headerLines.sublist(1, headerLines.length - 1);
    final stanzaLines =
        stanzaContent.splitBefore((line) => line.startsWith('->'));
    final stanzas = stanzaLines.map((e) => AgeStanza.parse(e.join('\n')));
    final mac = headerLines.last.replaceFirst('--- ', '');
    return AgeHeader._(stanzas.toList(), mac);
  }

  Future<String> serialize() async {
    return '${await headerWithoutMac(_stanzas)} $_mac';
  }

  static Future<String> headerWithoutMac(List<AgeStanza> stanzas) async {
    final header = StringBuffer();
    header.writeln('age-encryption.org/v1');
    for (var stanza in stanzas) {
      header.writeln(await stanza.serialize());
    }
    header.write('---');
    return header.toString();
  }

  Future<void> checkMac(Uint8List symmetricFileKey) async {
    final mac =
        await _calculateMac(await headerWithoutMac(_stanzas), symmetricFileKey);
    assert(mac == _mac, 'Incorrect mac');
  }

  static Future<String> _calculateMac(
      String header, Uint8List symmetricFileKey) async {
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final secretKeyData = SecretKeyData(symmetricFileKey);
    final macKey = await hkdfAlgorithm.deriveKey(
        secretKey: secretKeyData,
        nonce: Uint8List(1),
        info: 'header'.codeUnits);
    final mac = await hkdfAlgorithm.hmac
        .calculateMac(header.codeUnits, secretKey: macKey);
    return base64RawEncode(mac.bytes);
  }
}
