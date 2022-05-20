import 'dart:io';

import 'package:age_yubikey_pgp/interface.dart';
import 'package:age_yubikey_pgp/pin_provider.dart';
import 'package:age_yubikey_pgp/plugin.dart';
import 'package:age_yubikey_pgp/register.dart';
import 'package:args/args.dart';
import 'package:dage/dage.dart';
import 'package:logging/logging.dart';
import 'package:yubikit_openpgp/interface.dart';
import 'package:yubikit_openpgp/smartcard/interface.dart';

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

  final smartCardInterface = YubikeyPGPInterface(
      OpenPGPInterface(SmartCardInterface()), PinProvider());
  registerPlugin(smartCardInterface);

  final results = parseArguments(arguments);

  if (results['verbose']) {
    Logger.root.level = Level.FINE;
  }

  try {
    if (results['generate']) {
      final recipient =
          await YubikeyPgpX2559AgePlugin.generate(smartCardInterface);
      stdout.writeln(recipient.bytes);
    } else if (results['encrypt']) {
      final recipients = results['recipient'] as List<String>;
      var keyPairs =
          recipients.map((recipient) => AgeRecipient.fromBech32(recipient));
      if (keyPairs.isEmpty) {
        final recipient =
            await YubikeyPgpX2559AgePlugin.fromCard(smartCardInterface);
        if (recipient != null) {
          keyPairs = [recipient];
        }
      }
      final encrypted = encrypt(readFromInput(results), keyPairs.toList());
      writeToOut(results, encrypted);
    } else if (results['decrypt']) {
      final identityList = results['identity'] as List<String>;
      if (identityList.isNotEmpty) {
        final identities = await getIdentities(results);
        final decrypted = decrypt(readFromInput(results), identities);
        writeToOut(results, decrypted);
      } else {
        final recipient =
            await YubikeyPgpX2559AgePlugin.fromCard(smartCardInterface);
        if (recipient != null) {
          final decrypted =
              decrypt(readFromInput(results), [recipient.asKeyPair()]);
          writeToOut(results, decrypted);
        } else {
          throw Exception('Recipient not available!');
        }
      }
    } else {
      final recipient =
          await YubikeyPgpX2559AgePlugin.fromCard(smartCardInterface);
      stdout.writeln(recipient);
    }
  } catch (e, stacktrace) {
    logger.severe('Did not finish successfully', e, stacktrace);
    exit(1);
  }
}

Future<List<AgeKeyPair>> getIdentities(ArgResults results) async {
  final identityFiles = results['identity'] as List<String>;
  final keyPairs = await Future.wait(identityFiles.map((identityFile) async {
    final content = File(identityFile).readAsLinesSync();
    final key = content.firstWhere((element) => !element.startsWith('#'));
    return await AgePlugin.convertIdentityToKeyPair(
        AgeIdentity.fromBech32(key));
  }));
  return keyPairs.toList();
}

Stream<List<int>> readFromInput(ArgResults results) {
  if (results.rest.isNotEmpty) {
    final fileName = results.rest.last;
    return File(fileName).openRead();
  } else {
    return stdin;
  }
}

void writeToOut(ArgResults results, Stream<List<int>> bytes) {
  final output = results['output'];
  if (output != null) {
    File(output).openWrite().addStream(bytes);
  } else {
    stdout.addStream(bytes);
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
