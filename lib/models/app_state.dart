import 'package:flutter/foundation.dart';
import '../models/ip_addresses.dart';
import '../services/ip_service.dart';
import '../services/token_service.dart';

enum FetchStatus { idle, loading, success, error }

class AppState extends ChangeNotifier {
  String _token = '';
  IpAddresses? _addresses;
  FetchStatus _status = FetchStatus.idle;
  String? _errorMessage;

  String get token => _token;
  IpAddresses? get addresses => _addresses;
  FetchStatus get status => _status;
  String? get errorMessage => _errorMessage;

  /// Load the saved token from secure storage on app start.
  Future<void> loadToken() async {
    final saved = await TokenService.getToken();
    if (saved != null && saved.isNotEmpty) {
      _token = saved;
      notifyListeners();
    }
  }

  /// Persist a new token.
  Future<void> saveToken(String token) async {
    _token = token.trim();
    _addresses = null;
    _status = FetchStatus.idle;
    await TokenService.saveToken(_token);
    notifyListeners();
  }

  /// Fetch both IP addresses from ipinfo.io.
  Future<void> fetchAddresses() async {
    if (_token.isEmpty) {
      _errorMessage = 'Please configure your ipinfo.io token first.';
      _status = FetchStatus.error;
      notifyListeners();
      return;
    }

    _status = FetchStatus.loading;
    _errorMessage = null;
    notifyListeners();

    try {
      final result = await IpService.fetchAddresses(_token);
      if (!result.hasAny) {
        _errorMessage = 'No IP addresses returned. Check your token.';
        _status = FetchStatus.error;
      } else {
        _addresses = result;
        _status = FetchStatus.success;
      }
    } catch (e) {
      _errorMessage = 'Failed to fetch addresses: $e';
      _status = FetchStatus.error;
    }

    notifyListeners();
  }
}
