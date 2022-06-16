import 'package:dage/dage.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

import 'src/rsa/plugin.dart';
import 'src/x25519/plugin.dart';

export 'src/x25519/stanza.dart';
export 'src/rsa/stanza.dart';
export 'src/rsa/plugin.dart';
export 'src/x25519/plugin.dart';

void registerPlugin(YubikitOpenPGP interface) {
  AgePlugin.registerPlugin(YubikeyPgpX25519AgePlugin(interface));
  AgePlugin.registerPlugin(YubikeyPgpRsaAgePlugin(interface));
}
