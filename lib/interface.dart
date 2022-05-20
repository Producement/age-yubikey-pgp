import 'dart:typed_data';

import 'package:age_yubikey_pgp/pin_provider.dart';
import 'package:yubikit_openpgp/curve.dart';
import 'package:yubikit_openpgp/interface.dart';
import 'package:yubikit_openpgp/keyslot.dart';

class YubikeyPGPInterface {
  final OpenPGPInterface _openPGPInterface;
  final PinProvider _pinProvider;

  const YubikeyPGPInterface(this._openPGPInterface, this._pinProvider);

  Future<Uint8List> generateECKey() async {
    await _openPGPInterface.verifyAdmin(_pinProvider.adminPin());
    return _openPGPInterface.generateECKey(KeySlot.encryption, ECCurve.x25519);
  }

  Future<Uint8List?> getECPublicKey() async {
    return _openPGPInterface.getECPublicKey(KeySlot.encryption);
  }

  Future<Uint8List> ecSharedSecret(Uint8List recipientPublicKey) async {
    await _openPGPInterface.verifyPin(_pinProvider.pin());
    return _openPGPInterface.ecSharedSecret(recipientPublicKey);
  }
}
