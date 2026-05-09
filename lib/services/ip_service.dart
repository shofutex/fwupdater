import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/ip_addresses.dart';

class IpService {
  /// Fetches both IPv4 and IPv6 addresses from ipinfo.io in parallel.
  /// Each request independently succeeds or fails — if the device has no
  /// IPv6 connectivity, [ipv6] will be null and [ipv4] will still be returned.
  static Future<IpAddresses> fetchAddresses(String token) async {
    final results = await Future.wait([
      _fetchIpv4(token),
      _fetchIpv6(token),
    ]);

    return IpAddresses(
      ipv4: results[0],
      ipv6: results[1],
    );
  }

  static Future<String?> _fetchIpv4(String token) async {
    try {
      final uri = Uri.parse('https://ipinfo.io/').replace(
        queryParameters: {'token': token},
      );
      final response = await http
          .get(uri, headers: {'Accept': 'application/json'})
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        return data['ip'] as String?;
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  static Future<String?> _fetchIpv6(String token) async {
    try {
      final uri = Uri.parse('https://v6.ipinfo.io/').replace(
        queryParameters: {'token': token},
      );
      final response = await http
          .get(uri, headers: {'Accept': 'application/json'})
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        return data['ip'] as String?;
      }
      return null;
    } catch (_) {
      // IPv6 may be unavailable on the device/network — this is expected
      return null;
    }
  }
}
