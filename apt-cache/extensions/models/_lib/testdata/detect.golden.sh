#!/bin/sh
# Managed by @randybias/apt-cache. Static and tiny; runs as root.
# Prints the proxy URL when a TCP connect succeeds within 2s, else DIRECT.
if timeout 2 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ '192.0.2.10' '3142' 2>/dev/null; then
  printf '%s\n' 'http://192.0.2.10:3142'
else
  printf '%s\n' 'DIRECT'
fi
