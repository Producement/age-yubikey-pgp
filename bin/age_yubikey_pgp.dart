import 'dart:io';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/age/file.dart';
import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/pin_provider.dart';
import 'package:age_yubikey_pgp/src/yubikey/age/plugin.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/smartcard.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';
import 'package:args/args.dart';
import 'package:logging/logging.dart';

final logger = Logger('AgeYubikeyPGP');

void main(List<String> arguments) async {
  Logger.root.onRecord.listen((record) {
    stderr.writeln(record);
    if (record.error != null) {
      stderr.writeln(record.error);
    }
    if (record.stackTrace != null) {
      stderr.writeln(record.stackTrace);
    }
  });

  final pinProvider = PromptPinProvider();
  final smartCardInterface = YubikeySmartCardInterface(
      SmartCardInterface(), YubikeySmartCardCommand(), pinProvider);
  registerPlugins(smartCardInterface);

  final results = parseArguments(arguments);

  if (results['verbose']) {
    Logger.root.level = Level.FINE;
  }

  try {
    if (results['generate']) {
      final recipient = await YubikeyPgpAgePlugin.generate(smartCardInterface);
      stdout.writeln(recipient.bytes);
    } else if (results['encrypt']) {
      final input = File(results.rest.last).readAsBytesSync();
      final recipients = results['recipient'] as List<String>;
      var keyPairs =
          recipients.map((recipient) => AgeRecipient.fromBech32(recipient));
      if (keyPairs.isEmpty) {
        keyPairs = [await YubikeyPgpAgePlugin.fromCard(smartCardInterface)];
      }
      final encrypted = await AgeFile.encrypt(input, keyPairs.toList());
      writeToOut(results, encrypted.content);
    } else if (results['decrypt']) {
      final input = File(results.rest.last).readAsBytesSync();
      final newFile = AgeFile(input);
      final identityList = results['identity'] as List<String>;
      if (identityList.isNotEmpty) {
        final identities = await getIdentities(results, smartCardInterface);
        final decrypted = await newFile.decrypt(identities);
        writeToOut(results, decrypted);
      } else {
        final recipient =
            await YubikeyPgpAgePlugin.fromCard(smartCardInterface);
        final decrypted = await newFile.decrypt([recipient.asKeyPair()]);
        writeToOut(results, decrypted);
      }
    } else {
      final recipient = await YubikeyPgpAgePlugin.fromCard(smartCardInterface);
      stdout.writeln(recipient);
    }
  } catch (e, stacktrace) {
    logger.severe('Did not finish successfully', e, stacktrace);
    exit(1);
  }
}

Future<List<AgeKeyPair>> getIdentities(
    ArgResults results, YubikeySmartCardInterface smartCardInterface) async {
  final identityFiles = results['identity'] as List<String>;
  final keyPairs = await Future.wait(identityFiles.map((identityFile) async {
    final content = File(identityFile).readAsLinesSync();
    final key = content.firstWhere((element) => !element.startsWith('#'));
    return await AgePlugin.convertIdentityToKeyPair(
        AgeIdentity.fromBech32(key));
  }));
  return keyPairs.toList();
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

  parser.addFlag('generate',
      abbr: 'g', negatable: false, help: 'Generates new key on the Yubikey.');
  parser.addFlag('encrypt',
      abbr: 'e', negatable: false, help: 'Encrypt the input to the output.');
  parser.addFlag('decrypt',
      abbr: 'd', negatable: false, help: 'Decrypt the input to the output.');
  parser.addFlag('usage',
      abbr: 'u', negatable: false, help: 'Outputs this usage.');
  parser.addFlag('verbose',
      abbr: 'v', negatable: false, help: 'Enables logging to standard error.');
  parser.addOption('output',
      abbr: 'o', help: 'Write the result to the file at path.');
  parser.addMultiOption('recipient',
      abbr: 'r', help: 'Encrypt to the specified RECIPIENT. Can be repeated.');
  parser.addMultiOption('identity',
      abbr: 'i', help: 'Use the identity file at PATH. Can be repeated.');

  final results = parser.parse(arguments);

  if (results['usage']) {
    stdout.writeln(parser.usage);
    stdout.writeln('''

INPUT defaults to standard input, and OUTPUT defaults to standard output.
If OUTPUT exists, it will be overwritten.''');
    exit(0);
  }
  return results;
}