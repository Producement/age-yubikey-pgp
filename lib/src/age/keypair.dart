import 'dart:typed_data';

import 'package:bech32/bech32.dart';

class AgeKeypair {
  final Uint8List? _privateKey;
  final String? _privateKeyPrefix;
  final Uint8List _publicKey;
  final String _publicKeyPrefix;

  AgeKeypair(this._privateKey, this._privateKeyPrefix, this._publicKey,
      this._publicKeyPrefix);

  factory AgeKeypair.fromBech(String bechIdentity, bechPublicKey) {
    final privateKey = Bech32Decoder().convert(bechIdentity);
    final publicKey = Bech32Decoder().convert(bechPublicKey);
    return AgeKeypair(
        Uint8List.fromList(_convertBits(privateKey.data, 5, 8, false)),
        privateKey.hrp,
        Uint8List.fromList(_convertBits(publicKey.data, 5, 8, false)),
        publicKey.hrp);
  }

  factory AgeKeypair.fromPublic(String bechPublicKey) {
    final publicKey = Bech32Decoder().convert(bechPublicKey);
    return AgeKeypair(
        null,
        null,
        Uint8List.fromList(_convertBits(publicKey.data, 5, 8, false)),
        publicKey.hrp);
  }

  String get publicKey => _convertToBech32(_publicKeyPrefix, _publicKey)!;

  String get publicKeyPrefix => _publicKeyPrefix;

  Uint8List get publicKeyBytes => _publicKey;

  String? get privateKey {
    if (_privateKey == null) {
      return null;
    } else {
      return _convertToBech32(_privateKeyPrefix!, _privateKey)?.toUpperCase();
    }
  }

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
