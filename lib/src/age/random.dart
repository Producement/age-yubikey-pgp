import 'dart:math';
import 'dart:typed_data';

class AgeRandom {
  static final AgeRandom _singleton = AgeRandom._internal();

  factory AgeRandom() {
    return _singleton;
  }

  Uint8List bytes(int length) {
    final random = Random.secure();
    final data = Uint8List(length);
    for (int i = 0; i < length; i++) {
      data[i] = random.nextInt(256);
    }
    return data;
  }

  AgeRandom._internal();
}
