import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dage/dage.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

import 'src/stanza.dart';
import 'src/wrapped_key.dart';

export 'src/stanza.dart';

void registerPlugin(YubikitOpenPGP interface) {
  AgePlugin.registerPlugin(YubikeyPgpX25519AgePlugin(interface));
}

class YubikeyPgpX25519AgePlugin extends AgePlugin {
  static const publicKeyPrefix = 'age1yubikey1pgp';
  final YubikitOpenPGP _interface;

  YubikeyPgpX25519AgePlugin(this._interface);

  static Future<AgeRecipient> generate(YubikitOpenPGP openPGPInterface) async {
    final publicKey = await openPGPInterface.generateECKey(
        KeySlot.encryption, ECCurve.x25519);
    return AgeRecipient(
        publicKeyPrefix, Uint8List.fromList(publicKey.publicKey));
  }

  static Future<AgeRecipient?> fromCard(YubikitOpenPGP openPGPInterface) async {
    final publicKey = await openPGPInterface.getPublicKey(KeySlot.encryption);
    if (publicKey == null || publicKey is! ECKeyData) {
      return null;
    }
    return AgeRecipient(
        publicKeyPrefix, Uint8List.fromList(publicKey.publicKey));
  }

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    if (recipient.prefix != publicKeyPrefix) {
      return null;
    }
    return YubikeyX25519Stanza.create(
        _interface, recipient.bytes, symmetricFileKey, ephemeralKeyPair);
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, List<int> body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    if (arguments.isEmpty || arguments[0] != YubikeyX25519Stanza.tag) {
      return null;
    }
    if (arguments.length != 2) {
      throw Exception('Wrong amount of arguments: ${arguments.length}!');
    }
    final ephemeralShare = base64RawDecode(arguments[1]);
    if (ephemeralShare.length != 32) {
      throw Exception('Ephemeral share size is incorrect!');
    }
    if (body.length != 32) {
      throw Exception('Body size is incorrect!');
    }
    return YubikeyX25519Stanza(
        ephemeralShare, WrappedKey.fromRaw(body), _interface);
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) async {
    return null;
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      List<int> symmetricFileKey, List<int> salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    return null;
  }
}
