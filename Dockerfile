# Contexto de build = raiz do repositório.
# O servidor também serve os estáticos de ./web.
FROM node:22-alpine

WORKDIR /app
COPY server/package.json ./
RUN npm install --omit=dev

COPY server/src ./src
COPY web ./web

ENV NODE_ENV=production
USER node
EXPOSE 8090
CMD ["npx", "tsx", "src/index.ts"]
