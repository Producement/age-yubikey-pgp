library age_yubikey_pgp;

import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';
import 'package:dage/dage.dart';

void registerPlugins(YubikeySmartCardInterface smartCardInterface) {
  AgePlugin.registerPlugin(YubikeyPgpAgePlugin(smartCardInterface));
}
