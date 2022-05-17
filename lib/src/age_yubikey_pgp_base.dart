import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'smartcard/curve.dart';
import 'smartcard/fingerprint.dart';
import 'smartcard/instruction.dart';
import 'smartcard/keyslot.dart';
import 'smartcard/smartcard.dart';
import 'smartcard/tlv.dart';

class AgeYubikeyPGP {
  static const _prefix = "age1yubikey1pgp";

  Future<Uint8List> generateKeyPair() async {
    //Generate keypair on yubikey
    await verifyAdmin("12345678");
    final publicKey = await generateECKey(KeySlot.encryption, ECCurve.x25519);
    return publicKey;
  }

  Future<void> _verify(int pw, String pin) async {
    await sendApdu(
        0x00, Instruction.verify, 0, pw, Uint8List.fromList(pin.codeUnits));
  }

  Future<void> verifyPin(String pin) async {
    await _verify(0x82, pin);
  }

  Future<void> verifyAdmin(String pin) async {
    await _verify(0x83, pin);
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

  Future<Uint8List> generateECKey(KeySlot keySlot, ECCurve curve) async {
    Uint8List attributes = _formatECAttributes(keySlot, curve);
    await _setData(keySlot.keyId, attributes);
    Uint8List response =
        await sendApdu(0x00, Instruction.generateAsym, 0x80, 0x00, keySlot.crt);
    TlvData data = TlvData.parse(response).get(0x7F49);
    Uint8List publicKey = data.getValue(0x86);
    await _setData(
        keySlot.fingerprint,
        Uint8List.fromList(FingerprintCalculator.calculateFingerprint(
            BigInt.parse(hex.encode(publicKey), radix: 16), curve)));
    return publicKey;
  }

  Future<Uint8List> getECPublicKey(KeySlot keySlot, ECCurve curveName) async {
    Uint8List response =
        await sendApdu(0x00, Instruction.generateAsym, 0x81, 0x00, keySlot.crt);
    TlvData data = TlvData.parse(response).get(0x7F49);
    return data.getValue(0x86);
  }

  Future<Uint8List> ecSharedSecret(Uint8List publicKey) async {
    print("Packet length: ${publicKey.length}");
    print(hex.encode(publicKey));
    List<int> externalPublicKey = [0x86, publicKey.length] + publicKey;
    List<int> publicKeyDo =
        [0x7F49, externalPublicKey.length] + externalPublicKey;
    List<int> cipherDo = [0xA6, publicKeyDo.length] + publicKeyDo;
    Uint8List response = await sendApdu(
        0x00,
        Instruction.performSecurityOperation,
        0x80,
        0x86,
        Uint8List.fromList(cipherDo));
    return response;
  }

  Future<Uint8List> _getData(int cmd) async {
    Uint8List response = await sendApdu(0x00, Instruction.getData, cmd >> 8,
        cmd & 0xFF, Uint8List.fromList([]));
    return response;
  }

  Future<Uint8List> _setData(int cmd, Uint8List data) async {
    Uint8List response =
        await sendApdu(0x00, Instruction.putData, cmd >> 8, cmd & 0xFF, data);
    return response;
  }

  Future<Uint8List> sendApdu(
      int cla, Instruction instruction, int p1, int p2, Uint8List data) async {
    if (data.lengthInBytes > 0) {
      Uint8List command = Uint8List.fromList(
          [cla, instruction.value, p1, p2, data.lengthInBytes] + data);
      return sendApduToCard(
        command,
      );
    } else {
      Uint8List command = Uint8List.fromList([cla, instruction.value, p1, p2]);
      return sendApduToCard(command);
    }
  }
}
