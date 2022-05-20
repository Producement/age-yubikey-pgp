import 'package:age_yubikey_pgp/interface.dart';
import 'package:age_yubikey_pgp/pin_provider.dart';
import 'package:age_yubikey_pgp/plugin.dart';
import 'package:age_yubikey_pgp/register.dart';
import 'package:collection/collection.dart';
import 'package:dage/dage.dart';
import 'package:yubikit_openpgp/interface.dart';
import 'package:yubikit_openpgp/smartcard/interface.dart';

void main() async {
  final smartCardInterface = YubikeyPGPInterface(
      OpenPGPInterface(SmartCardInterface()), PinProvider());
  registerPlugin(smartCardInterface);

  // Generate key on card
  final recipient = await YubikeyPgpX2559AgePlugin.generate(smartCardInterface);

  // Encrypt to recipient
  final encrypted = encrypt(Stream.value('Hello World'.codeUnits), [recipient]);

  final recipientFromCard =
      await YubikeyPgpX2559AgePlugin.fromCard(smartCardInterface);
  if (recipientFromCard != null) {
    // Decrypt
    final decrypted = decrypt(encrypted, [recipientFromCard.asKeyPair()]);
    final asList = await decrypted.toList();
    assert('Hello World'.codeUnits == asList.flattened);
  }
}
