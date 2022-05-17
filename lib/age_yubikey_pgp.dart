library age_yubikey_pgp;

import 'package:age_yubikey_pgp/src/age/plugin.dart';
import 'package:age_yubikey_pgp/src/age/x25519.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/smartcard.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';

void registerPlugins() {
  final x25519Plugin = X25519AgePlugin();
  AgePlugin.registerPlugin(x25519Plugin);
  final smartCardInterface = YubikeySmartCardInterface(
      SmartCardInterface(), YubikeySmartCardCommand());
  final pinProvider = PromptYubikeyPinProvider();
  final yubikeyPlugin = YubikeyPgpAgePlugin(smartCardInterface, pinProvider);
  AgePlugin.registerPlugin(yubikeyPlugin);
}