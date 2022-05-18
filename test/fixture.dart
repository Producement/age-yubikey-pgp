import 'dart:io';
import 'dart:typed_data';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/age/random.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';

import 'yubikey/yubikey_smartcard_interface_test.mocks.dart';

final recipient = AgeRecipient.fromBech32(
    'age12v6newahxev3mukn7tmr2ycvu5wa0tzkf2yuwret3j8mjg49mggqnawwlu');
final identity = AgeIdentity.fromBech32(
    'AGE-SECRET-KEY-13W6UT6Z3H72N3YY9MXJMPPMN2K0KQGW863HPH258UCUXKLK3S3RQA32XH3');
final recipientKeyPair = AgeKeyPair(identity, recipient);

final algorithm = X25519();

final symmetricFileKey =
    Uint8List.fromList(hex.decode('3055884752f3bb977b673798c6521579'));

final smartCardInterface = YubikeySmartCardInterface(
    MockSmartCardInterface(), MockYubikeySmartCardCommand(), MockPinProvider());

void registerPluginsMock() {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((record) {
    stderr.writeln(record);
    if (record.error != null) {
      stderr.writeln(record.error);
    }
    if (record.stackTrace != null) {
      stderr.writeln(record.stackTrace);
    }
  });
  registerPlugins(smartCardInterface);
}

class ConstAgeRandom implements AgeRandom {
  @override
  Uint8List bytes(int length) {
    return Uint8List.fromList(List.generate(length, (index) => 0x01));
  }
}