import 'dart:typed_data';

import 'package:bech32/bech32.dart';

class AgeKeypair {
  static const _pkPrefix = "age";
  static const _identityPrefix = "AGE-SECRET-KEY-";

  final Uint8List? _privateKey;
  final Uint8List _publicKey;

  AgeKeypair._(this._privateKey, this._publicKey);

  factory AgeKeypair(String bechIdentity, bechPublicKey) {
    return AgeKeypair._(
        Uint8List.fromList(_convertBits(
            Bech32Decoder().convert(bechIdentity).data, 5, 8, false)),
        Uint8List.fromList(_convertBits(
            Bech32Decoder().convert(bechPublicKey).data, 5, 8, false)));
  }

  static AgeKeypair fromPublic(String bechPublicKey) {
    return AgeKeypair._(
        null,
        Uint8List.fromList(_convertBits(
            Bech32Decoder().convert(bechPublicKey).data, 5, 8, false)));
  }

  String get publicKey => _convertToBech32(_pkPrefix, _publicKey)!;

  Uint8List get publicKeyBytes => _publicKey;

  String? get privateKey =>
      _convertToBech32(_identityPrefix, _privateKey)?.toUpperCase();

  Uint8List? get privateKeyBytes => _privateKey;

  static String? _convertToBech32(String prefix, Uint8List? key) {
    if (key == null) {
      return null;
    }
    final bech32 = Bech32(prefix, _convertBits(key, 8, 5, true));
    return Bech32Encoder().convert(bech32);
  }

  static List<int> _convertBits(List<int> data, int from, int to, bool pad) {
    var acc = 0;
    var bits = 0;
    var result = <int>[];
    var maxv = (1 << to) - 1;

    for (var v in data) {
      if (v < 0 || (v >> from) != 0) {
        throw Exception();
      }
      acc = (acc << from) | v;
      bits += from;
      while (bits >= to) {
        bits -= to;
        result.add((acc >> bits) & maxv);
      }
    }

    if (pad) {
      if (bits > 0) {
        result.add((acc << (to - bits)) & maxv);
      }
    } else if (bits >= from) {
      throw InvalidPadding('illegal zero padding');
    } else if (((acc << (to - bits)) & maxv) != 0) {
      throw InvalidPadding('non zero');
    }

    return result;
  }
}
