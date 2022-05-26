import 'dart:typed_data';

import 'package:age_yubikey_pgp/pin_provider.dart';
import 'package:yubikit_openpgp/yubikit_openpgp.dart';

class AgeYubikeyPGPInterface {
  final YubikitOpenPGP _openPGPInterface;
  final PinProvider _pinProvider;

  const AgeYubikeyPGPInterface(this._openPGPInterface, this._pinProvider);

  Future<Uint8List> generateECKey(KeySlot keySlot, ECCurve curve) async {
    await _openPGPInterface.verifyAdmin(_pinProvider.adminPin());
    return _openPGPInterface.generateECKey(keySlot, curve);
  }

  Future<Uint8List?> getECPublicKey(KeySlot keySlot) async {
    return _openPGPInterface.getECPublicKey(keySlot);
  }

  Future<Uint8List> ecSharedSecret(Uint8List recipientPublicKey) async {
    await _openPGPInterface.verifyPin(_pinProvider.pin());
    return _openPGPInterface.ecSharedSecret(recipientPublicKey);
  }
}
