# Contexto de build = raiz do repositório.
# Inclui Redis embutido para deploy em um único serviço (Railway).
FROM node:22-alpine

RUN apk add --no-cache redis

WORKDIR /app
COPY server/package.json ./
RUN npm install --omit=dev

COPY server/src ./src
COPY web ./web
COPY redis/redis.embed.conf ./redis.embed.conf
COPY scripts/start.sh ./start.sh
RUN chmod +x ./start.sh && mkdir -p /tmp/redis && chown -R node:node /tmp/redis /app

# No Railway as variáveis do serviço entram no build. Falhamos aqui se
# faltar o essencial — evita imagem “ok” que só quebra ao subir.
# Em build local (docker compose) RAILWAY_* não existe e a checagem é pulada.
RUN if [ -n "${RAILWAY_ENVIRONMENT:-}${RAILWAY_PROJECT_ID:-}" ]; then \
      missing=""; \
      [ -n "${ROTATION_TOKEN:-}" ] || missing="$missing ROTATION_TOKEN"; \
      [ -n "${GROUP_TOKEN:-}" ] || missing="$missing GROUP_TOKEN"; \
      if [ -n "$missing" ]; then \
        echo "Sigilo: configure no Railway (Variables) antes do build:$missing" >&2; \
        exit 1; \
      fi; \
    fi

ENV NODE_ENV=production
ENV REDIS_URL=redis://127.0.0.1:6379
USER node
EXPOSE 8090
CMD ["./start.sh"]
