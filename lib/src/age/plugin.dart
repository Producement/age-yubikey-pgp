import 'dart:typed_data';

import 'package:age_yubikey_pgp/src/age/keypair.dart';
import 'package:age_yubikey_pgp/src/age/stanza.dart';
import 'package:cryptography/cryptography.dart';

abstract class AgePlugin {
  static final List<AgePlugin> _plugins = [];

  AgePlugin();

  static void registerPlugin(AgePlugin p) {
    _plugins.add(p);
  }

  AgeStanza? parseStanza(List<String> arguments, Uint8List body);

  Future<AgeStanza?> createStanza(
      AgeKeypair recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]);

  static AgeStanza? stanzaParse(List<String> arguments, Uint8List body) {
    for (var plugin in _plugins) {
      final stanza = plugin.parseStanza(arguments, body);
      if (stanza != null) {
        return stanza;
      }
    }
    return null;
  }

  static Future<AgeStanza> stanzaCreate(
      AgeKeypair recipient, Uint8List symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    for (var plugin in _plugins) {
      final stanza = await plugin.createStanza(
          recipient, symmetricFileKey, ephemeralKeyPair);
      if (stanza != null) {
        return stanza;
      }
    }
    throw Exception('Could not create stanza!');
  }
}
