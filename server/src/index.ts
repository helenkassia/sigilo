import { env } from "./env.js";
import { formatDuration } from "./duration.js";
import { createHttpServer } from "./http.js";
import { attachRelay } from "./relay.js";

const server = createHttpServer();
attachRelay(server);

server.listen(env.port, () => {
  console.log(`sigilo :: http+ws em :${env.port}`);
  console.log(
    `vida da mensagem: padrão ${formatDuration(env.msgTtl)} ` +
      `(${formatDuration(env.msgTtlMin)}–${formatDuration(env.msgTtlMax)}), contada da criação`,
  );
  console.log(`opções na interface: ${env.ttlOptions.map(formatDuration).join(", ")}`);
  console.log("chave de empacotamento apenas em memória");
});

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    // Encerrar o processo já descarta a chave de empacotamento; tudo que
    // ainda estava no Redis vira ruído indecifrável.
    server.close(() => process.exit(0));
  });
}
