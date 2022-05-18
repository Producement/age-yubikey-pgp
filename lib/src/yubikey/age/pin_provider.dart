import 'dart:io';

abstract class PinProvider {
  String pin();

  String adminPin();
}

class PromptPinProvider extends PinProvider {
  @override
  String adminPin() {
    print('Enter admin pin:');
    stdin.echoMode = false;
    return stdin.readLineSync()!;
  }

  @override
  String pin() {
    print('Enter pin:');
    stdin.echoMode = false;
    return stdin.readLineSync()!;
  }
}
