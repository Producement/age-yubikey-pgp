import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/rsa/stanza.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dage/dage.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

class YubikeyPgpRsaAgePlugin extends AgePlugin {
  static const publicKeyPrefix = 'age1yubikey1pgp1rsa';
  final YubikitOpenPGP _interface;

  const YubikeyPgpRsaAgePlugin(this._interface);

  static Future<AgeRecipient> generate(YubikitOpenPGP openPGPInterface,
      [int keySize = 2048]) async {
    final publicKey =
        await openPGPInterface.generateRSAKey(KeySlot.encryption, keySize);
    return _parseRecipient(publicKey.modulus, publicKey.exponent);
  }

  static Future<AgeRecipient?> fromCard(YubikitOpenPGP openPGPInterface) async {
    final publicKey = await openPGPInterface.getPublicKey(KeySlot.encryption);
    if (publicKey == null || publicKey is! RSAKeyData) {
      return null;
    }
    return _parseRecipient(publicKey.modulus, publicKey.exponent);
  }

  static AgeRecipient _parseRecipient(List<int> modulus, List<int> exponent) {
    return AgeRecipient(
        YubikeyPgpRsaAgePlugin.publicKeyPrefix,
        Uint8List.fromList([
          modulus.length >> 8,
          modulus.length & 0xFF,
          ...modulus,
          ...exponent
        ]));
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      List<int> symmetricFileKey, List<int> salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    return null;
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [KeyPair? ephemeralKeyPair]) async {
    if (recipient.prefix != publicKeyPrefix) {
      return null;
    }
    return YubikeyRsaStanza.create(_interface, recipient, symmetricFileKey);
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) async {
    return null;
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, List<int> body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    if (arguments.isEmpty || arguments[0] != YubikeyRsaStanza.tag) {
      return null;
    }
    return YubikeyRsaStanza.parse(arguments, body, _interface);
  }
}
