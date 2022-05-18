import 'dart:io';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/age/file.dart';
import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/pin_provider.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/smartcard.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';
import 'package:args/args.dart';
import 'package:logging/logging.dart';

void main(List<String> arguments) async {
  Logger.root.onRecord.listen((record) {
    stderr.writeln('${record.level.name}: ${record.time}: ${record.message}');
  });

  final pinProvider = PromptPinProvider();
  final smartCardInterface = YubikeySmartCardInterface(
      SmartCardInterface(), YubikeySmartCardCommand(), pinProvider);
  registerPlugins(smartCardInterface);

  final results = parseArguments(arguments);

  if (results['verbose']) {
    Logger.root.level = Level.FINE;
  }

  if (results['generate']) {
    final keyPair = await YubikeyX25519Keypair.generate(smartCardInterface);
    stdout.writeln(keyPair.publicKey);
  } else if (results['encrypt']) {
    final input = File(results.rest.last).readAsBytesSync();
    final recipients = results['recipient'] as List<String>;
    final keyPairs =
        recipients.map((recipient) => AgeKeypair.fromPublic(recipient));
    final encrypted = await AgeFile.encrypt(input, keyPairs.toList());
    writeToOut(results, encrypted.content);
  } else if (results['decrypt']) {
    final input = File(results.rest.last).readAsBytesSync();
    final newFile = AgeFile(input);
    final keyPair = await YubikeyX25519Keypair.fromCard(smartCardInterface);
    final decrypted = await newFile.decrypt([keyPair]);
    writeToOut(results, decrypted);
  } else {
    final keyPair = await YubikeyX25519Keypair.fromCard(smartCardInterface);
    stdout.writeln(keyPair.publicKey);
  }
}

void writeToOut(ArgResults results, List<int> bytes) {
  final output = results['output'];
  if (output != null) {
    File(output).writeAsBytesSync(bytes);
  } else {
    stdout.add(bytes);
  }
}

ArgResults parseArguments(List<String> arguments) {
  final parser = ArgParser();

  parser.addFlag('generate', abbr: 'g', negatable: false);
  parser.addFlag('encrypt', abbr: 'e', negatable: false);
  parser.addFlag('decrypt', abbr: 'd', negatable: false);
  parser.addFlag('usage', abbr: 'u', negatable: false);
  parser.addFlag('verbose', abbr: 'v', negatable: false);
  parser.addOption('output', abbr: 'o');
  parser.addMultiOption('recipient', abbr: 'r');

  final results = parser.parse(arguments);

  if (results['usage']) {
    stdout.writeln(parser.usage);
    exit(0);
  }
  return results;
}