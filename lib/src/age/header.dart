import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:age_yubikey_pgp/src/util.dart';
import 'package:cryptography/cryptography.dart';

class AgeHeader {
  final List<AgeStanza> _stanzas;

  AgeHeader(this._stanzas);

  Future<Uint8List> serialize(Uint8List symmetricFileKey) async {
    final header = StringBuffer();
    header.writeln("age-encryption.org/v1");
    for (var stanza in _stanzas) {
      header.writeln(await stanza.serialize(symmetricFileKey));
    }
    header.write("---");
    header.write(" ${await _mac(header.toString(), symmetricFileKey)}");
    return Uint8List.fromList(header.toString().codeUnits);
  }

  Future<String> _mac(String header, Uint8List symmetricFileKey) async {
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final secretKeyData = SecretKeyData(symmetricFileKey);
    final macKey = await hkdfAlgorithm.deriveKey(
        secretKey: secretKeyData,
        nonce: Uint8List(1),
        info: "header".codeUnits);
    final mac = await hkdfAlgorithm.hmac
        .calculateMac(header.codeUnits, secretKey: macKey);
    return base64Raw(mac.bytes);
  }
}