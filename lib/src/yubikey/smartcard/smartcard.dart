import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';

abstract class SmartCardInterface {
  Future<Uint8List> sendCommand(String command);

  Future<Uint8List> sendApduToCard(List<int> input);

  SmartCardInterface._();

  factory SmartCardInterface() {
    return GPGConnectAgentSmartCardInterface._();
  }

  Future<Uint8List> fetchKeyMaterialFromCard(List<int> publicKey) async {
    publicKey = publicKey.skip(1).toList();
    final pkLength = publicKey.length;
    await sendCommand('00 20 00 82 06 31 32 33 34 35 36');
    final sharedSecret =
        await sendCommand('00 2a 80 86 ${(pkLength + 7).toRadixString(16)} '
            'a6 ${(pkLength + 5).toRadixString(16)} '
            '7f 49 ${(pkLength + 2).toRadixString(16)} '
            '86 ${pkLength.toRadixString(16)} ${_hexWithSpaces(publicKey)}');
    return sharedSecret;
  }

  String _hexWithSpaces(List<int> input) {
    if (input.isEmpty) {
      return '';
    }
    String command = '';
    for (var item in input) {
      command += '${hex.encode([item])} ';
    }
    return command.substring(0, command.length - 1);
  }
}

class GPGConnectAgentSmartCardInterface extends SmartCardInterface {
  GPGConnectAgentSmartCardInterface._() : super._();

  @override
  Future<Uint8List> sendCommand(String command) async {
    return sendApduToCard(hex.decode(command.replaceAll(' ', '')));
  }

// 90 00 OK
  final _successfulEnd = [144, 0, 10, 79, 75, 10];

  @override
  Future<Uint8List> sendApduToCard(List<int> input) async {
    String command = 'scd apdu ${_hexWithSpaces(input)}';
    print('Sending command: $command}');
    var processResult =
        await Process.run('gpg-connect-agent', [command], stdoutEncoding: null);
    List<int> result = processResult.stdout;
    Function eq = const ListEquality().equals;
    if (!eq(result.skip(result.length - _successfulEnd.length).toList(),
        _successfulEnd)) {
      final errorCode =
          result.skip(result.length - _successfulEnd.length).take(2).toList();
      throw Exception('Error from smartcard ${_hexWithSpaces(errorCode)}');
    }
    final processedResult = result.skip(2).take(result.length - 8).toList();
    print('Command result: ${_hexWithSpaces(processedResult)}');
    return Uint8List.fromList(processedResult);
  }
}