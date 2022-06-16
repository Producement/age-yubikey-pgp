import 'dart:typed_data';

import 'package:dage/dage.dart';
import 'package:pointycastle/export.dart';
import 'package:yubikit_openpgp/utils.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

class YubikeyRsaStanza extends AgeStanza {
  static const tag = 'YUBIRSA';

  final List<int> _wrappedKey;
  final YubikitOpenPGP _interface;
  final int _keySize;

  const YubikeyRsaStanza._internal(
      this._wrappedKey, this._keySize, this._interface);

  factory YubikeyRsaStanza.parse(
      List<String> arguments, List<int> body, YubikitOpenPGP interface) {
    if (arguments.length != 2) {
      throw Exception('Wrong amount of arguments: ${arguments.length}!');
    }
    final keyLength = int.parse(arguments[1]) ~/ 8;
    if (keyLength % 128 != 0) {
      throw Exception('Key length is incorrect!');
    }
    if (body.length != keyLength) {
      throw Exception('Body size is incorrect (${body.length}!=$keyLength)!');
    }
    return YubikeyRsaStanza._internal(body, keyLength, interface);
  }

  static Future<YubikeyRsaStanza> create(YubikitOpenPGP interface,
      AgeRecipient recipient, List<int> symmetricFileKey) async {
    final cipher = PKCS1Encoding(RSAEngine());
    cipher.init(
        true,
        PublicKeyParameter<RSAPublicKey>(
            RSAPublicKey(_modulus(recipient), _exponent(recipient))));
    final encryptedKey = cipher.process(Uint8List.fromList(symmetricFileKey));
    return YubikeyRsaStanza._internal(
      encryptedKey,
      _modulusLength(recipient),
      interface,
    );
  }

  static int _modulusLength(AgeRecipient recipient) {
    final lengthBytes = ByteData(2)
      ..setUint8(0, recipient.bytes[0])
      ..setUint8(1, recipient.bytes[1]);
    return lengthBytes.getUint16(0);
  }

  static BigInt _modulus(AgeRecipient recipient) {
    return PGPUtils.intListToBigInt(
        recipient.bytes.sublist(2).take(_modulusLength(recipient)).toList());
  }

  static BigInt _exponent(AgeRecipient recipient) {
    return PGPUtils.intListToBigInt(
        recipient.bytes.sublist(2 + _modulusLength(recipient)));
  }

  @override
  Future<Uint8List> decryptedFileKey(AgeKeyPair? keyPair) async {
    return _interface.decipher(_wrappedKey);
  }

  @override
  Future<String> serialize() async {
    final header = '-> $tag ${_keySize * 8}';
    final body = base64RawEncode(_wrappedKey);
    return '${wrapAtPosition(header)}\n${wrapAtPosition(body)}';
  }
}
