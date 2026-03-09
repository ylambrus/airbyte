# Changelog

## 0.3.0

Add an option to force lowercase topic names.

- Add `topic_names_lowercase` option (default: `false`), applied after the naming convention transformation

## 0.2.0

Add SSL certificate authentication support.

- Add SSL protocol support with PEM certificate format for mutual TLS authentication
- Implement secure temporary file handling with cleanup hooks for SSL certificates
- Add comprehensive SSL configuration options (keystore, truststore, endpoint identification)

## 0.1.11

Previous release.
