import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/yubikey/age/pin_provider.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/curve.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/keyslot.dart';
import 'package:test/test.dart';

import 'package:age_yubikey_pgp/src/yubikey/smartcard/smartcard.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_interface.dart';

import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'yubikey_smartcard_interface_test.mocks.dart';

@GenerateMocks([YubikeySmartCardCommand, SmartCardInterface, PinProvider])
void main() {
  final smartCardInterface = MockSmartCardInterface();
  final yubikeyCommand = MockYubikeySmartCardCommand();
  final pinProvider = MockPinProvider();
  final yubikeyInterface = YubikeySmartCardInterface(
      smartCardInterface, yubikeyCommand, pinProvider);

  test('generate keypair', () async {
    final adminPin = '12345678';
    final expectedPublicKey = Uint8List.fromList([
      27,
      45,
      97,
      5,
      232,
      18,
      82,
      145,
      249,
      215,
      189,
      218,
      59,
      192,
      70,
      228,
      214,
      37,
      48,
      65,
      60,
      54,
      70,
      228,
      163,
      193,
      84,
      44,
      118,
      50,
      159,
      124
    ]);

    final verifyPinCommand = Uint8List.fromList([1, 2, 3]);
    final verifyPinResponse = Uint8List.fromList([2, 3, 4]);

    final setKeyAttributesCommand = Uint8List.fromList([3, 4, 5]);
    final setKeyAttributesResponse = Uint8List.fromList([4, 5, 6]);

    final generateKeyCommand = Uint8List.fromList([5, 6, 7]);
    final generateKeyResponse = Uint8List.fromList([127, 73, 34, 134] +
        [expectedPublicKey.length] +
        expectedPublicKey +
        [169, 127]);

    final setFingerprintCommand = Uint8List.fromList([7, 8, 9]);
    final setFingerprintResponse = Uint8List.fromList([8, 9, 0]);

    when(pinProvider.adminPin()).thenReturn(adminPin);
    when(yubikeyCommand.verifyAdmin(adminPin)).thenReturn(verifyPinCommand);
    when(smartCardInterface.sendCommand(verifyPinCommand))
        .thenAnswer((_) async => verifyPinResponse);

    when(yubikeyCommand.setKeyAttributes(KeySlot.encryption, ECCurve.x25519))
        .thenReturn(setKeyAttributesCommand);
    when(smartCardInterface.sendCommand(setKeyAttributesCommand))
        .thenAnswer((_) async => setKeyAttributesResponse);

    when(yubikeyCommand.generateKey(KeySlot.encryption))
        .thenReturn(generateKeyCommand);
    when(smartCardInterface.sendCommand(generateKeyCommand))
        .thenAnswer((_) async => generateKeyResponse);

    when(yubikeyCommand.setFingerprint(
            KeySlot.encryption, ECCurve.x25519, expectedPublicKey))
        .thenReturn(setFingerprintCommand);
    when(smartCardInterface.sendCommand(setFingerprintCommand))
        .thenAnswer((_) async => setFingerprintResponse);

    final publicKey = await yubikeyInterface.generateKeyPair();

    expect(publicKey, equals(expectedPublicKey));
  });
}
