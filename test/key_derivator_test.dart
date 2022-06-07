import 'package:age_yubikey_pgp/src/key_derivator.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  final algorithm = X25519();
  final keyDerivator = KeyDerivator();
  late SimpleKeyPair ephemeralKeyPair;
  late SimpleKeyPair keyPair;

  setUp(() async {
    ephemeralKeyPair =
        await algorithm.newKeyPairFromSeed(List.generate(32, (index) => 0x01));
    keyPair =
        await algorithm.newKeyPairFromSeed(List.generate(32, (index) => 0x03));
  });
  test('derives the same key', () async {
    final sharedSecret1 = await algorithm.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: await ephemeralKeyPair.extractPublicKey());
    final derivedKey1 = await keyDerivator.derive(
        sharedSecret1,
        (await keyPair.extractPublicKey()).bytes,
        (await ephemeralKeyPair.extractPublicKey()).bytes);
    final sharedSecret2 = await algorithm.sharedSecretKey(
        keyPair: ephemeralKeyPair,
        remotePublicKey: await keyPair.extractPublicKey());
    final derivedKey2 = await keyDerivator.derive(
        sharedSecret2,
        (await keyPair.extractPublicKey()).bytes,
        (await ephemeralKeyPair.extractPublicKey()).bytes);
    expect(derivedKey1, equals(derivedKey2));
  });
}
