import 'dart:convert';
import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/bits.dart';
import 'package:age_yubikey_pgp/src/tlv.dart';
import 'package:basic_utils/basic_utils.dart' as utils;
import 'package:bech32/bech32.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';

import 'curve.dart';
import 'fingerprint.dart';
import 'instruction.dart';
import 'keyslot.dart';
import 'smartcard.dart';

class AgeYubikeyPGP {
  static const _prefix = "age1yubikey1pgp";

  Future<String> generateKeyPair() async {
    //Generate keypair on yubikey
    await verifyAdmin("12345678");
    final publicKey = await generateECKey(KeySlot.encryption, ECCurve.x25519);
    return convertToBech32(publicKey);
  }

  String convertToBech32(Uint8List publicKey) {
    final bech32 = Bech32(_prefix, publicKey.toBits(5));
    return Bech32Encoder().convert(bech32);
  }

  Future<String> stanza(
      Uint8List symmetricFileKey, Uint8List recipientPublicKey,
      [SimpleKeyPair? keyPair]) async {
    final algorithm = X25519();
    keyPair ??= await algorithm.newKeyPair();
    final publicKey = await keyPair.extractPublicKey();
    final cipherTextPublicKey =
        base64.encode(publicKey.bytes).replaceAll("=", "");

    final List<int> salt = publicKey.bytes + recipientPublicKey;
    final info = "age-encryption.org/v1/X25519";
    final remotePublicKey =
        SimplePublicKey(recipientPublicKey, type: KeyPairType.x25519);
    var sharedSecret = await algorithm.sharedSecretKey(
        keyPair: keyPair, remotePublicKey: remotePublicKey);

    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final derivedKey = await hkdfAlgorithm.deriveKey(
        secretKey: sharedSecret, info: info.codeUnits, nonce: salt);

    final wrappingAlgorithm = Chacha20.poly1305Aead();
    final body = await wrappingAlgorithm.encrypt(symmetricFileKey,
        secretKey: derivedKey, nonce: List.generate(12, (index) => 0x00));
    final header = "-> X25519 $cipherTextPublicKey";
    final base64Body =
        base64.encode(body.concatenation(nonce: false)).replaceAll("=", "");
    final wrappedHeader =
        utils.StringUtils.addCharAtPosition(header, "\n", 64, repeat: true);
    final wrappedBody =
        utils.StringUtils.addCharAtPosition(base64Body, "\n", 64, repeat: true);
    return "$wrappedHeader\n$wrappedBody";
  }

  Future<String> headerMac(String header, Uint8List symmetricFileKey) async {
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final secretKeyData = SecretKeyData(symmetricFileKey);
    final macKey = await hkdfAlgorithm.deriveKey(
        secretKey: secretKeyData,
        nonce: Uint8List(1),
        info: "header".codeUnits);
    final mac = await hkdfAlgorithm.hmac
        .calculateMac(header.codeUnits, secretKey: macKey);
    final base64Mac = base64.encode(mac.bytes).replaceAll("=", "");
    return base64Mac;
  }

  Future<List<int>> encrypt(String input, Uint8List recipientPublicKey,
      [Uint8List? symmetricFileKey,
      SimpleKeyPair? keyPair,
      Uint8List? nonce]) async {
    symmetricFileKey ??=
        Uint8List.fromList(SecretKeyData.random(length: 16).bytes);
    final recipientStanza =
        await stanza(symmetricFileKey, recipientPublicKey, keyPair);
    final header = "age-encryption.org/v1\n$recipientStanza\n---";
    final mac = await headerMac(header, symmetricFileKey);
    nonce ??= Uint8List.fromList(SecretKeyData.random(length: 16).bytes);
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: nonce,
        info: "payload".codeUnits);
    final encryptionAlgorithm = Chacha20.poly1305Aead();
    final secretBox = await encryptionAlgorithm.encrypt(input.codeUnits,
        nonce: List.generate(11, (index) => 0) + [0x01], secretKey: payloadKey);
    final payloadNonce = List.generate(16, (index) => 1);
    return header.codeUnits +
        " ".codeUnits +
        mac.codeUnits +
        "\n".codeUnits +
        payloadNonce +
        secretBox.concatenation(nonce: false);
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