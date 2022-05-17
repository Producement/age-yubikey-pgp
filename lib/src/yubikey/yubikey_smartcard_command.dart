import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'smartcard/curve.dart';
import 'smartcard/fingerprint.dart';
import 'smartcard/instruction.dart';
import 'smartcard/keyslot.dart';

class YubikeySmartCardCommand {
  YubikeySmartCardCommand();

  Uint8List verifyAdmin(String pin) {
    return _verify(0x83, pin);
  }

  Uint8List verifyPin(String pin) {
    return _verify(0x82, pin);
  }

  Uint8List _verify(int pw, String pin) {
    return _createCommand(
        0x00, Instruction.verify, 0, pw, Uint8List.fromList(pin.codeUnits));
  }

  Uint8List generateKey(KeySlot keySlot) {
    return _createCommand(
        0x00, Instruction.generateAsym, 0x80, 0x00, keySlot.crt);
  }

  Uint8List setFingerprint(KeySlot keySlot, ECCurve curve, Uint8List publicKey,
      [int? timestamp]) {
    return _setData(
        keySlot.fingerprint,
        Uint8List.fromList(FingerprintCalculator.calculateFingerprint(
            BigInt.parse(hex.encode(publicKey), radix: 16), curve, timestamp)));
  }

  Uint8List _formatECAttributes(KeySlot keySlot, ECCurve curve) {
    late int algorithm;
    if ([ECCurve.ed25519, ECCurve.x25519].contains(curve)) {
      algorithm = 0x16;
    } else if (keySlot == KeySlot.encryption) {
      algorithm = 0x12;
    } else {
      algorithm = 0x13;
    }
    return Uint8List.fromList([algorithm].followedBy(curve.oid).toList());
  }

  Uint8List setKeyAttributes(KeySlot keySlot, ECCurve curve) {
    final attributes = _formatECAttributes(keySlot, curve);
    return _setData(keySlot.keyId, attributes);
  }

  Uint8List getECPublicKey(KeySlot keySlot) {
    return _createCommand(
        0x00, Instruction.generateAsym, 0x81, 0x00, keySlot.crt);
  }

  Uint8List getSharedSecret(Uint8List publicKey) {
    final externalPublicKey = [0x86, publicKey.length] + publicKey;
    final publicKeyDataObject =
        [0x7F49, externalPublicKey.length] + externalPublicKey;
    final cipherDataObject =
        [0xA6, publicKeyDataObject.length] + publicKeyDataObject;
    return _createCommand(0x00, Instruction.performSecurityOperation, 0x80,
        0x86, Uint8List.fromList(cipherDataObject));
  }

  Uint8List _setData(int cmd, Uint8List data) {
    return _createCommand(
        0x00, Instruction.putData, cmd >> 8, cmd & 0xFF, data);
  }

  Uint8List _createCommand(int clazz, Instruction instruction, int param1,
      int param2, Uint8List data) {
    if (data.lengthInBytes > 0) {
      return Uint8List.fromList([
            clazz,
            instruction.value,
            param1,
            param2,
            data.lengthInBytes
          ] +
          data);
    } else {
      return Uint8List.fromList([clazz, instruction.value, param1, param2]);
    }
  }
}
