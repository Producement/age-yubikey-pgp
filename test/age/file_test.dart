import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/file.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

import '../fixture.dart';

void main() {
  test('encrypt', () async {
    final file = AgeFile(Uint8List.fromList("sinu ema".codeUnits));
    final nonce = Uint8List.fromList(List.generate(16, (index) => 1));
    final ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    var encrypted = await file.encryptWithEphemeralKeypair(
        [recipientKeyPair.publicKeyBytes],
        symmetricFileKey: symmetricFileKey,
        keyPair: ephemeralKeyPair,
        payloadNonce: nonce);
    final dataAsEncryptedBytes =
        hex.decode("5fe918b39a0ad95a56205d9eba2a3d560118df011fd530ff");
    expect(
        encrypted,
        orderedEquals('''age-encryption.org/v1
-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q
1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE
--- hnTNhYFvWIIs53UDE1UqyW/PYyLD3zFmDJPTMS7/s8U
'''
                .codeUnits +
            nonce +
            dataAsEncryptedBytes));
  });
}