import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/header.dart';
import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:test/test.dart';

import '../fixture.dart';

void main() {
  test('header', () async {
    final ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    final stanza = await AgeStanza.create(
        symmetricFileKey, recipientKeyPair.publicKeyBytes, ephemeralKeyPair);
    final header = AgeHeader([stanza], symmetricFileKey);
    expect(String.fromCharCodes(await header.serialize()),
        equals('''age-encryption.org/v1
${await stanza.serialize()}
--- hnTNhYFvWIIs53UDE1UqyW/PYyLD3zFmDJPTMS7/s8U'''));
  });
}
