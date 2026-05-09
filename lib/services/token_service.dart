import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class TokenService {
  static const _key = 'ipinfo_token';

  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static Future<String?> getToken() async {
    return _storage.read(key: _key);
  }

  static Future<void> saveToken(String token) async {
    await _storage.write(key: _key, value: token);
  }

  static Future<void> deleteToken() async {
    await _storage.delete(key: _key);
  }
}
