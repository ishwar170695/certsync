#!/bin/sh
export NODE_USE_SYSTEM_CA=1
DIR="$(dirname "$0")"
exec "$DIR/node-real" "$@"
