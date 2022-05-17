import 'dart:typed_data';

import 'smartcard/curve.dart';
import 'smartcard/keyslot.dart';
import 'smartcard/smartcard.dart';
import 'smartcard/tlv.dart';
import 'yubikey_smartcard_command.dart';

class YubikeySmartCardInterface {
  final YubikeySmartCardCommand _yubikeyCommand;
  final SmartCardInterface _smartCardInterface;

  YubikeySmartCardInterface(this._smartCardInterface, this._yubikeyCommand);

  Future<Uint8List> generateKeyPair(String adminPin) async {
    final verifyPin = _yubikeyCommand.verifyAdmin(adminPin);
    await _smartCardInterface.sendApduToCard(verifyPin);
    var publicKey = _generateECKey(KeySlot.encryption, ECCurve.x25519);
    return publicKey;
  }

  Future<Uint8List> getPublicKey() async {
    final command = _yubikeyCommand.getECPublicKey(KeySlot.encryption);
    final response = await _smartCardInterface.sendApduToCard(command);
    return _getPublicKey(response);
  }

  Future<Uint8List> calculateSharedSecret(
      Uint8List recipientPublicKey, String pin) async {
    final verifyPin = _yubikeyCommand.verifyPin(pin);
    await _smartCardInterface.sendApduToCard(verifyPin);
    final sharedSecretCommand =
        _yubikeyCommand.getSharedSecret(recipientPublicKey);
    return await _smartCardInterface.sendApduToCard(sharedSecretCommand);
  }

  Future<Uint8List> _generateECKey(KeySlot keySlot, ECCurve curve) async {
    final setKeyAttributes = _yubikeyCommand.setKeyAttributes(keySlot, curve);
    await _smartCardInterface.sendApduToCard(setKeyAttributes);

    final generateKeyCommand = _yubikeyCommand.generateKey(keySlot);
    final response =
        await _smartCardInterface.sendApduToCard(generateKeyCommand);

    final publicKey = _getPublicKey(response);
    final setFingerprintCommand =
        _yubikeyCommand.setFingerprint(keySlot, curve, publicKey);
    await _smartCardInterface.sendApduToCard(setFingerprintCommand);

    return publicKey;
  }

  Uint8List _getPublicKey(Uint8List generateKeyResponse) {
    final data = TlvData.parse(generateKeyResponse).get(0x7F49);
    return data.getValue(0x86);
  }
}
