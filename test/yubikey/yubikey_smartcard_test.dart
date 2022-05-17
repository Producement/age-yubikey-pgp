import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/yubikey/smartcard/curve.dart';
import 'package:age_yubikey_pgp/src/yubikey/smartcard/keyslot.dart';
import 'package:age_yubikey_pgp/src/yubikey/yubikey_smartcard_command.dart';
import 'package:test/test.dart';

void main() {
  final yubikeyCommand = YubikeySmartCardCommand();

  test('verify admin', () {
    final pin = '12345678';
    final verifyAdminPinCommand = yubikeyCommand.verifyAdmin(pin);
    expect(verifyAdminPinCommand,
        orderedEquals([0, 32, 0, 131, 8, 49, 50, 51, 52, 53, 54, 55, 56]));
  });

  test('verify pin', () {
    final pin = '123456';
    final verifyPinCommand = yubikeyCommand.verifyPin(pin);
    expect(verifyPinCommand,
        orderedEquals([0, 32, 0, 130, 6, 49, 50, 51, 52, 53, 54]));
  });

  test('set key attributes', () {
    final setKeyAttributesCommand =
        yubikeyCommand.setKeyAttributes(KeySlot.encryption, ECCurve.x25519);
    expect(
        setKeyAttributesCommand,
        orderedEquals(
            [0, 218, 0, 194, 11, 22, 43, 6, 1, 4, 1, 151, 85, 1, 5, 1]));
  });

  test('generate key', () {
    final generateKeyCommand = yubikeyCommand.generateKey(KeySlot.encryption);
    expect(generateKeyCommand, orderedEquals([0, 71, 128, 0, 2, 184, 0]));
  });

  test('set fingerprint', () {
    final publicKey = Uint8List.fromList([2, 3, 4]);
    final timestamp = 1652807883;
    final setFingerprintCommand = yubikeyCommand.setFingerprint(
        KeySlot.encryption, ECCurve.x25519, publicKey, timestamp);
    expect(
        setFingerprintCommand,
        orderedEquals([
          0,
          218,
          0,
          200,
          20,
          44,
          155,
          98,
          172,
          60,
          55,
          227,
          98,
          255,
          90,
          83,
          8,
          191,
          244,
          123,
          15,
          153,
          255,
          186,
          62
        ]));
  });

  test('get public key', () {
    var getPublicKeyCommand = yubikeyCommand.getECPublicKey(KeySlot.encryption);
    expect(getPublicKeyCommand, orderedEquals([0, 71, 129, 0, 2, 184, 0]));
  });

  test('get shared secret', () {
    final recipientPublicKey = Uint8List.fromList([6, 7, 8]);
    final sharedSecretCommand =
        yubikeyCommand.getSharedSecret(recipientPublicKey);
    expect(
        sharedSecretCommand,
        orderedEquals(
            [0, 42, 128, 134, 10, 166, 8, 127, 73, 5, 134, 3, 6, 7, 8]));
  });
}