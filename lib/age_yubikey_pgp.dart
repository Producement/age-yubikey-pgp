library age_yubikey_pgp;

import 'package:age_yubikey_pgp/src/age/plugin.dart';
import 'package:age_yubikey_pgp/src/age/x25519.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';

void registerPlugins(YubikeySmartCardInterface smartCardInterface) {
  final x25519Plugin = X25519AgePlugin();
  AgePlugin.registerPlugin(x25519Plugin);
  final yubikeyPlugin = YubikeyPgpAgePlugin(smartCardInterface);
  AgePlugin.registerPlugin(yubikeyPlugin);
}
