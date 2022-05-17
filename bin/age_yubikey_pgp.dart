import 'dart:io';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/age/file.dart';
import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/smartcard.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';
import 'package:args/args.dart';
import 'package:logging/logging.dart';

void main(List<String> arguments) async {
  Logger.root.level = Level.OFF;
  Logger.root.onRecord.listen((record) {
    stderr.writeln('${record.level.name}: ${record.time}: ${record.message}');
  });

  final smartCardInterface = YubikeySmartCardInterface(
      SmartCardInterface(), YubikeySmartCardCommand());
  final pinProvider = PromptYubikeyPinProvider();
  registerPlugins(smartCardInterface, pinProvider);

  final parser = ArgParser();

  parser.addFlag('generate', abbr: 'g', negatable: false);
  parser.addFlag('encrypt', abbr: 'e', negatable: false);
  parser.addFlag('decrypt', abbr: 'd', negatable: false);
  parser.addFlag('usage', abbr: 'u', negatable: false);
  parser.addFlag('verbose', abbr: 'v', negatable: false);
  parser.addOption('output', abbr: 'o');
  parser.addMultiOption('recipient', abbr: 'r');

  final results = parser.parse(arguments);

  if (results['verbose']) {
    Logger.root.level = Level.FINE;
  }

  if (results['usage']) {
    stdout.writeln(parser.usage);
  } else if (results['generate']) {
    final keyPair =
        await YubikeyX25519Keypair.generate(smartCardInterface, pinProvider);
    stdout.writeln(keyPair.publicKey);
  } else if (results['encrypt']) {
    final input = File(results.rest.last).readAsBytesSync();
    final data = AgeFile(input);
    final recipients = results['recipient'] as List<String>;
    final keyPairs =
        recipients.map((recipient) => AgeKeypair.fromPublic(recipient));
    final encrypted = await data.encrypt(keyPairs.toList());
    final output = results['output'];
    if (output != null) {
      File(output).writeAsBytesSync(encrypted);
    } else {
      stdout.add(encrypted);
    }
    File('${results.rest.last}.age').writeAsBytesSync(encrypted);
  } else if (results['decrypt']) {
    final input = File(results.rest.last).readAsBytesSync();
    final newFile = AgeFile(input);
    final keyPair = await YubikeyX25519Keypair.fromCard(smartCardInterface);
    final decrypted = await newFile.decrypt([keyPair]);
    final output = results['output'];
    if (output != null) {
      File(output).writeAsBytesSync(decrypted);
    } else {
      stdout.add(decrypted);
    }
  } else {
    final keyPair = await YubikeyX25519Keypair.fromCard(smartCardInterface);
    stdout.writeln(keyPair.publicKey);
  }
}
