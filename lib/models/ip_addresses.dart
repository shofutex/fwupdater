class IpAddresses {
  final String? ipv4;
  final String? ipv6;

  const IpAddresses({this.ipv4, this.ipv6});

  bool get hasAny => ipv4 != null || ipv6 != null;

  @override
  String toString() => 'IpAddresses(ipv4: $ipv4, ipv6: $ipv6)';
}
