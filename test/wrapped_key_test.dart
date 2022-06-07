import 'package:age_yubikey_pgp/src/wrapped_key.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  final algorithm = X25519();
  late SimpleKeyPair ephemeralKeyPair;
  late SimpleKeyPair keyPair;

  setUp(() async {
    ephemeralKeyPair =
        await algorithm.newKeyPairFromSeed(List.generate(32, (index) => 0x01));
    keyPair =
        await algorithm.newKeyPairFromSeed(List.generate(32, (index) => 0x03));
  });

  test('wraps/unwraps key', () async {
    final key = [0, 1, 2, 3, 4, 5];
    final encryptionSharedSecret = await algorithm.sharedSecretKey(
        keyPair: ephemeralKeyPair,
        remotePublicKey: await keyPair.extractPublicKey());
    final wrappedKey = WrappedKey(key, encryptionSharedSecret);
    final decryptionSharedSecret = await algorithm.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: await ephemeralKeyPair.extractPublicKey());
    expect(await wrappedKey.unwrap(decryptionSharedSecret), equals(key));
  });
}
