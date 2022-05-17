import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:test/test.dart';

import '../fixture.dart';

void main() {
  test('age recipient stanza', () async {
    final ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    final stanza = await AgeStanza.create(
        recipientKeyPair.publicKeyBytes, ephemeralKeyPair);
    expect(
        await stanza.serialize(symmetricFileKey),
        equals("-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q\n"
            "1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE"));
  });
}