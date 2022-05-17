import 'dart:typed_data';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/age/file.dart';
import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/smartcard.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';

void main(List<String> arguments) async {
  print('###START');
  registerPlugins();
  final smartCardInterface = YubikeySmartCardInterface(
      SmartCardInterface(), YubikeySmartCardCommand());

  late AgeKeypair keyPair;
  try {
    keyPair = await YubikeyX25519Keypair.fromCard(smartCardInterface);
    print('###USE EXISTING KEY');
  } catch (e) {
    print('###GENERATE NEW KEY');
    keyPair = await YubikeyX25519Keypair.generate(
        smartCardInterface, PromptYubikeyPinProvider());
  }
  final data = AgeFile(Uint8List.fromList('Hello World'.codeUnits));
  final file = await data.encrypt([keyPair]);
  print(String.fromCharCodes(file));
  print('###');
  final newFile = AgeFile(file);
  final decrypted = await newFile.decrypt([keyPair]);
  print(String.fromCharCodes(decrypted));
  print('###END');
}