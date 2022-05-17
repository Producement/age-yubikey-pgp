import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/header.dart';
import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:test/test.dart';

import '../fixture.dart';

void main() {
  test('header', () async {
    final ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    final stanza = await AgeStanza.create(
        recipientKeyPair.publicKeyBytes, ephemeralKeyPair);
    final header = AgeHeader([stanza]);
    expect(String.fromCharCodes(await header.serialize(symmetricFileKey)),
        equals('''age-encryption.org/v1
${await stanza.serialize(symmetricFileKey)}
--- hnTNhYFvWIIs53UDE1UqyW/PYyLD3zFmDJPTMS7/s8U'''));
  });
}