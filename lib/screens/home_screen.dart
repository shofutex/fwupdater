import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../models/app_state.dart';
import 'settings_screen.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('IP Check'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            tooltip: 'Settings',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const SettingsScreen()),
            ),
          ),
        ],
      ),
      body: Consumer<AppState>(
        builder: (context, state, _) {
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // ── Token warning ──────────────────────────────────────────
                if (state.token.isEmpty)
                  _TokenWarningBanner(theme: theme),

                const Spacer(),

                // ── Button 1: Fetch ────────────────────────────────────────
                FilledButton.icon(
                  onPressed: state.status == FetchStatus.loading
                      ? null
                      : () => context.read<AppState>().fetchAddresses(),
                  icon: state.status == FetchStatus.loading
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : const Icon(Icons.refresh),
                  label: Text(
                    state.status == FetchStatus.loading
                        ? 'Fetching…'
                        : 'Fetch IP Addresses',
                  ),
                  style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    textStyle: theme.textTheme.titleMedium,
                  ),
                ),

                const SizedBox(height: 16),

                // ── Button 2: Display ──────────────────────────────────────
                OutlinedButton.icon(
                  onPressed: (state.addresses != null &&
                          state.status == FetchStatus.success)
                      ? () => _showAddressesDialog(context, state)
                      : null,
                  icon: const Icon(Icons.info_outline),
                  label: const Text('Show IP Addresses'),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    textStyle: theme.textTheme.titleMedium,
                  ),
                ),

                const SizedBox(height: 32),

                // ── Status / result inline preview ─────────────────────────
                _StatusArea(state: state, theme: theme),

                const Spacer(),
              ],
            ),
          );
        },
      ),
    );
  }

  void _showAddressesDialog(BuildContext context, AppState state) {
    final addr = state.addresses!;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Your IP Addresses'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _AddressRow(label: 'IPv4', value: addr.ipv4),
            const SizedBox(height: 16),
            _AddressRow(label: 'IPv6', value: addr.ipv6),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}

// ── Supporting widgets ──────────────────────────────────────────────────────

class _TokenWarningBanner extends StatelessWidget {
  final ThemeData theme;
  const _TokenWarningBanner({required this.theme});

  @override
  Widget build(BuildContext context) {
    return Card(
      color: theme.colorScheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Icon(Icons.warning_amber_rounded,
                color: theme.colorScheme.onErrorContainer),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'No API token set. Tap the ⚙ icon to add your ipinfo.io token.',
                style: TextStyle(color: theme.colorScheme.onErrorContainer),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _StatusArea extends StatelessWidget {
  final AppState state;
  final ThemeData theme;
  const _StatusArea({required this.state, required this.theme});

  @override
  Widget build(BuildContext context) {
    switch (state.status) {
      case FetchStatus.idle:
        return Center(
          child: Text(
            'Press "Fetch IP Addresses" to begin.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        );
      case FetchStatus.loading:
        return const Center(child: CircularProgressIndicator());
      case FetchStatus.error:
        return Card(
          color: theme.colorScheme.errorContainer,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              state.errorMessage ?? 'Unknown error.',
              style: TextStyle(color: theme.colorScheme.onErrorContainer),
            ),
          ),
        );
      case FetchStatus.success:
        final addr = state.addresses!;
        return Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _AddressRow(label: 'IPv4', value: addr.ipv4),
                const SizedBox(height: 12),
                _AddressRow(label: 'IPv6', value: addr.ipv6),
              ],
            ),
          ),
        );
    }
  }
}

class _AddressRow extends StatelessWidget {
  final String label;
  final String? value;
  const _AddressRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final display = value ?? 'Not available';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: theme.textTheme.labelSmall?.copyWith(
              color: theme.colorScheme.primary,
              fontWeight: FontWeight.bold,
              letterSpacing: 1.2,
            )),
        const SizedBox(height: 4),
        GestureDetector(
          onLongPress: value != null
              ? () {
                  Clipboard.setData(ClipboardData(text: value!));
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('$label address copied.')),
                  );
                }
              : null,
          child: Text(
            display,
            style: theme.textTheme.bodyLarge?.copyWith(
              fontFamily: 'monospace',
              color: value != null
                  ? theme.colorScheme.onSurface
                  : theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ),
        if (value != null)
          Text('Long-press to copy',
              style: theme.textTheme.labelSmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              )),
      ],
    );
  }
}
