import 'dart:typed_data';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/smartcard.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';

final recipientKeyPair = AgeKeypair.fromBech(
    'AGE-SECRET-KEY-13W6UT6Z3H72N3YY9MXJMPPMN2K0KQGW863HPH258UCUXKLK3S3RQA32XH3',
    'age12v6newahxev3mukn7tmr2ycvu5wa0tzkf2yuwret3j8mjg49mggqnawwlu');

final algorithm = X25519();

final symmetricFileKey =
    Uint8List.fromList(hex.decode('3055884752f3bb977b673798c6521579'));

final smartCardInterface =
    YubikeySmartCardInterface(SmartCardInterface(), YubikeySmartCardCommand());

class MockPinProvider extends YubikeyPinProvider {
  @override
  String provideAdminPin() {
    throw UnimplementedError();
  }

  @override
  String providePin() {
    throw UnimplementedError();
  }
}

void registerPluginsMock() =>
    registerPlugins(smartCardInterface, MockPinProvider());
