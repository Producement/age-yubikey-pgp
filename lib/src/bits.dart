import 'dart:typed_data';

import 'package:bech32/bech32.dart';

List<int> _convertBits(List<int> data, int from, int to, bool pad) {
  var acc = 0;
  var bits = 0;
  var result = <int>[];
  var maxv = (1 << to) - 1;

  data.forEach((v) {
    if (v < 0 || (v >> from) != 0) {
      throw Exception();
    }
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      result.add((acc >> bits) & maxv);
    }
  });

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

extension Uint8ToOther on Uint8List {
  List<int> toBits(int bits) => _convertBits(this, 8, bits, true);
}

extension OtherToUint8 on List<int> {
  toUint8List(int bits) {
    return Uint8List.fromList(_convertBits(this, bits, 8, false));
  }
}
