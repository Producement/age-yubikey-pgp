import 'package:cryptography/cryptography.dart';

class KeyDerivator {
  static const _info = 'YUBIX25519';
  final _hkdfAlgorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );

  Future<SecretKey> derive(SecretKey sharedSecret, List<int> recipientPublicKey,
      List<int> ephemeralPublicKey) async {
    final salt = ephemeralPublicKey + recipientPublicKey;
    final derivedKey = await _hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: _info.codeUnits, nonce: salt);
    return derivedKey;
  }
}
