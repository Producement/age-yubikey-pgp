import 'dart:typed_data';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:age_yubikey_pgp/src/age/x25519.dart';
import 'package:test/test.dart';

import '../fixture.dart';

void main() {
  setUpAll(() => registerPlugins());

  final serializedStanza =
      '-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q\n'
      '1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE';
  test('create age recipient stanza', () async {
    final ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    final stanza = await X25519AgeStanza.create(
        recipientKeyPair.publicKeyBytes, symmetricFileKey, ephemeralKeyPair);
    expect(await stanza.serialize(), equals(serializedStanza));
  });

  test('parse age recipient stanza', () async {
    final parsed = AgeStanza.parse(serializedStanza);
    expect(parsed.runtimeType, equals(X25519AgeStanza));
    expect(await parsed.serialize(), equals(serializedStanza));
  });
}
