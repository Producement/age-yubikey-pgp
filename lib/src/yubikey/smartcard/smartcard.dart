import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:logging/logging.dart';

abstract class SmartCardInterface {
  Future<Uint8List> sendCommand(List<int> input);

  SmartCardInterface._internal();

  factory SmartCardInterface() {
    return GPGConnectAgentSmartCardInterface._internal();
  }
}

class GPGConnectAgentSmartCardInterface extends SmartCardInterface {
  static final logger = Logger('GPGConnectAgentSmartCardInterface');

  GPGConnectAgentSmartCardInterface._internal() : super._internal();

// 90 00 OK
  final _successfulEnd = [144, 0, 10, 79, 75, 10];

  @override
  Future<Uint8List> sendCommand(List<int> input) async {
    String command = 'scd apdu ${_hexWithSpaces(input)}';
    logger.fine('Sending command: $command}');
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
    logger.fine('Command result: ${_hexWithSpaces(processedResult)}');
    return Uint8List.fromList(processedResult);
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
