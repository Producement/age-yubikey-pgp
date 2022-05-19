import 'dart:io';

class PinProvider {
  const PinProvider();

  String adminPin() {
    print('Enter admin pin:');
    stdin.echoMode = false;
    return stdin.readLineSync()!;
  }

  String pin() {
    print('Enter pin:');
    stdin.echoMode = false;
    return stdin.readLineSync()!;
  }
}
