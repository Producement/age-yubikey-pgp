import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:age_yubikey_pgp/age_yubikey_pgp.dart';
import 'package:age_yubikey_pgp/src/bits.dart';
import 'package:bech32/bech32.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('Age Yubikey PGP tests', () {
    final age = AgeYubikeyPGP();
    //# created: 2022-05-16T14:16:17+03:00
    //# public key: age12v6newahxev3mukn7tmr2ycvu5wa0tzkf2yuwret3j8mjg49mggqnawwlu
    //AGE-SECRET-KEY-13W6UT6Z3H72N3YY9MXJMPPMN2K0KQGW863HPH258UCUXKLK3S3RQA32XH3

    final recipientPrivateKey = Bech32Decoder()
        .convert(
            "AGE-SECRET-KEY-13W6UT6Z3H72N3YY9MXJMPPMN2K0KQGW863HPH258UCUXKLK3S3RQA32XH3")
        .data
        .toUint8List(5);
    final recipientPublicKey = Bech32Decoder()
        .convert(
            "age12v6newahxev3mukn7tmr2ycvu5wa0tzkf2yuwret3j8mjg49mggqnawwlu")
        .data
        .toUint8List(5);
    final symmetricFileKey =
        Uint8List.fromList(hex.decode("3055884752f3bb977b673798c6521579"));
    final algorithm = X25519();
    final nonce = Uint8List.fromList(List.generate(16, (index) => 1));
    late SimpleKeyPair ephemeralKeyPair;

    setUp(() async {
      ephemeralKeyPair = await algorithm.newKeyPairFromSeed(Uint8List(32));
    });

    test('Public key has proper prefix', () async {
      var pubKey = await age.generateKeyPair();
      expect(pubKey, startsWith("age1yubikey1pgp1"));
    }, skip: 'uses smartcard');

    test('convert public key to bech32 format', () {
      expect(
          age.convertToBech32(recipientPublicKey),
          equals(
              "age1yubikey1pgp12v6newahxev3mukn7tmr2ycvu5wa0tzkf2yuwret3j8mjg49mggql28jwa"));
    });

    test('recipient stanza', () async {
      final stanza = await age.stanza(
          symmetricFileKey, recipientPublicKey, ephemeralKeyPair);
      expect(
          stanza,
          equals("-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q\n"
              "1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE"));
    });

    test('header mac', () async {
      final header = "age-encryption.org/v1\n"
          "-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q\n"
          "1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE\n"
          "---";
      var mac = await age.headerMac(header, symmetricFileKey);
      expect(mac, equals("hnTNhYFvWIIs53UDE1UqyW/PYyLD3zFmDJPTMS7/s8U"));
    });

    test('encrypt', () async {
      var encrypted = await age.encrypt("sinu ema", recipientPublicKey,
          symmetricFileKey, ephemeralKeyPair, nonce);
      final encryptedAsString = String.fromCharCodes(encrypted);
      print(Directory.current);
      await File("text.age").writeAsBytes(encrypted);
      await File("text2.age").writeAsBytes(encrypted);
    });

    test('decrypt file key', () async {
      final keyPair = SimpleKeyPairData(recipientPrivateKey,
          publicKey:
              SimplePublicKey(recipientPublicKey, type: KeyPairType.x25519),
          type: KeyPairType.x25519);
      final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();
      final sharedSecret = await algorithm.sharedSecretKey(
          keyPair: keyPair, remotePublicKey: ephemeralPublicKey);

      final hkdfAlgorithm = Hkdf(
        hmac: Hmac(Sha256()),
        outputLength: 32,
      );
      final info = "age-encryption.org/v1/X25519";
      final List<int> salt = ephemeralPublicKey.bytes + recipientPublicKey;
      final derivedKey = await hkdfAlgorithm.deriveKey(
          secretKey: sharedSecret, info: info.codeUnits, nonce: salt);
      final secret =
          base64Decode("1cT9u0o55LQ9SVnYROZh6SqATr3CGseHSlgf4YMD4LE=");
      final wrappingAlgorithm = Chacha20.poly1305Aead();
      final secretBox = SecretBox.fromConcatenation(
          List.generate(12, (index) => 0x00) + secret,
          macLength: 16,
          nonceLength: 12);
      final body =
          await wrappingAlgorithm.decrypt(secretBox, secretKey: derivedKey);
      expect(body, equals(symmetricFileKey.toList()));
    });
  });

  group('Age format tests', () {});
}