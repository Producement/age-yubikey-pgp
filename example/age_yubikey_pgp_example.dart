import 'dart:convert';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:collection/collection.dart';
import 'package:dage/dage.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

void main() async {
  final smartCardInterface =
      YubikitOpenPGP(const SmartCardInterface(), PinProvider());
  registerPlugin(smartCardInterface);

  // Generate key on card
  final recipient =
      await YubikeyPgpX25519AgePlugin.generate(smartCardInterface);

  // Encrypt to recipient
  final encrypted = encrypt(Stream.value('Hello World'.codeUnits), [recipient]);

  final recipientFromCard =
      await YubikeyPgpX25519AgePlugin.fromCard(smartCardInterface);
  if (recipientFromCard != null) {
    // Decrypt
    final decrypted = decrypt(encrypted, [recipientFromCard.asKeyPair()]);
    final asList = await decrypted.toList();
    assert('Hello World' == utf8.decode(asList.flattened.toList()));
  }
}
