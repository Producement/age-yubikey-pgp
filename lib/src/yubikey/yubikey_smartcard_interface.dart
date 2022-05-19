import 'dart:typed_data';

import 'pin_provider.dart';
import 'smartcard/curve.dart';
import 'smartcard/keyslot.dart';
import 'smartcard/smartcard.dart';
import 'smartcard/tlv.dart';
import 'yubikey_smartcard_command.dart';

class YubikeySmartCardInterface {
  final YubikeySmartCardCommand _yubikeyCommand;
  final SmartCardInterface _smartCardInterface;
  final PinProvider pinProvider;

  YubikeySmartCardInterface(this._smartCardInterface, this._yubikeyCommand,
      {this.pinProvider = const PinProvider()});

  Future<Uint8List> generateKeyPair() async {
    final verifyPin = _yubikeyCommand.verifyAdmin(pinProvider.adminPin());
    await _smartCardInterface.sendCommand(verifyPin);
    var publicKey = _generateECKey(KeySlot.encryption, ECCurve.x25519);
    return publicKey;
  }

  Future<Uint8List> getPublicKey() async {
    final command = _yubikeyCommand.getECPublicKey(KeySlot.encryption);
    final response = await _smartCardInterface.sendCommand(command);
    return _getPublicKey(response);
  }

  Future<Uint8List> calculateSharedSecret(Uint8List recipientPublicKey) async {
    final verifyPin = _yubikeyCommand.verifyPin(pinProvider.pin());
    await _smartCardInterface.sendCommand(verifyPin);
    final sharedSecretCommand =
        _yubikeyCommand.getSharedSecret(recipientPublicKey);
    return await _smartCardInterface.sendCommand(sharedSecretCommand);
  }

  Future<Uint8List> _generateECKey(KeySlot keySlot, ECCurve curve) async {
    final setKeyAttributes = _yubikeyCommand.setKeyAttributes(keySlot, curve);
    await _smartCardInterface.sendCommand(setKeyAttributes);

    final generateKeyCommand = _yubikeyCommand.generateKey(keySlot);
    final response = await _smartCardInterface.sendCommand(generateKeyCommand);

    final publicKey = _getPublicKey(response);
    final setFingerprintCommand =
        _yubikeyCommand.setFingerprint(keySlot, curve, publicKey);
    await _smartCardInterface.sendCommand(setFingerprintCommand);

    return publicKey;
  }

  Uint8List _getPublicKey(Uint8List generateKeyResponse) {
    final data = TlvData.parse(generateKeyResponse).get(0x7F49);
    return data.getValue(0x86);
  }
}
