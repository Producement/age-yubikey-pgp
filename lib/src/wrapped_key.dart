import 'package:cryptography/cryptography.dart';
import 'package:dage/dage.dart';

class WrappedKey {
  static final _wrappingAlgorithm = Chacha20.poly1305Aead();
  static final _wrappingNonce = List.generate(12, (index) => 0x00);
  final Future<List<int>> _wrappedKey;

  WrappedKey(List<int> rawKey, SecretKey derivedKey)
      : _wrappedKey = _wrap(rawKey, derivedKey);

  WrappedKey.fromRaw(List<int> wrappedKey)
      : _wrappedKey = Future.value(wrappedKey);

  Future<String> get base64 async => base64RawEncode(await _wrappedKey);

  static Future<List<int>> _wrap(
      List<int> symmetricFileKey, SecretKey derivedKey) async {
    final body = await _wrappingAlgorithm.encrypt(symmetricFileKey,
        secretKey: derivedKey, nonce: _wrappingNonce);
    return body.concatenation(nonce: false);
  }

  Future<List<int>> unwrap(SecretKey derivedKey) async {
    final secretBox = SecretBox.fromConcatenation(
        _wrappingNonce + await _wrappedKey,
        macLength: 16,
        nonceLength: 12);
    return await _wrappingAlgorithm.decrypt(secretBox, secretKey: derivedKey);
  }
}
