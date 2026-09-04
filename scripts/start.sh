#!/bin/sh
# Sobe Redis local (se necessário) e o relay do Sigilo no mesmo container.
set -eu

iniciar_redis_local() {
  mkdir -p /tmp/redis
  redis-server /app/redis.embed.conf --daemonize yes
  i=0
  while [ "$i" -lt 30 ]; do
    if redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q PONG; then
      return 0
    fi
    i=$((i + 1))
    sleep 0.2
  done
  echo "Redis embutido não respondeu a tempo." >&2
  return 1
}

url="${REDIS_URL:-}"
if [ -z "$url" ] || printf '%s' "$url" | grep -Eq '127\.0\.0\.1|localhost'; then
  iniciar_redis_local
  export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
fi

exec npx tsx src/index.ts
