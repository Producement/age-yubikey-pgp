library src;

import 'package:age_yubikey_pgp/interface.dart';
import 'package:age_yubikey_pgp/plugin.dart';
import 'package:dage/dage.dart';

void registerPlugin(YubikeyPGPInterface smartCardInterface) {
  AgePlugin.registerPlugin(YubikeyPgpX2559AgePlugin(smartCardInterface));
}