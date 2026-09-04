# Sigilo

Chat interno de mensagens autodestrutivas. Criptografia ponta a ponta no
navegador, mensagens apenas em memória (Redis sem persistência), servidor
zero-knowledge.

O servidor nunca vê o conteúdo. Não é uma promessa de configuração — ele
não tem como ver: a chave de decifra nunca sai do dispositivo do usuário.

## Como rodar

```bash
cp .env.example .env   # e troque os segredos
docker compose up --build
```

**Desenvolvimento (hot reload):** monta `server/src` e `web` e reinicia o
Node ao salvar. Frontend: só atualizar a página (F5).

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Abra `http://localhost:8090`, entre com um identificador e você já está no
`#geral`. Para conversa direta, busque o identificador da pessoa e confira a
impressão digital antes de escrever.

Para testar com várias pessoas no mesmo computador, use **navegadores
diferentes** (ou janelas anônimas separadas) — abas do mesmo navegador
compartilham o IndexedDB e, com ele, as identidades e as chaves fixadas.

## Enviando

O compositor tem duas decisões, e a frase à direita diz sempre o que vai
acontecer com a mensagem antes de você mandar:

- **some em** — o prazo, de `5m` a `7d`.
- **some assim que for lida** — queima no ato da leitura, com o prazo como
  teto para o caso de ninguém ler.

Passando o mouse sobre uma mensagem sua aparece **excluir**, que apaga todas
as cópias imediatamente.

Uma mensagem de queima deixa uma **lápide** dos dois lados: o texto some, o
registro de que houve uma mensagem fica.

- **quem enviou** vê a lápide assim que a mensagem é lida —
  *"lida · o texto não existe mais"*, com a hora e, em canal, quantos leram;
- **quem recebeu** lê o texto normalmente enquanto está na conversa, com
  borda tracejada âmbar avisando que já foi destruído no servidor. Ao sair da
  conversa o texto vai embora e fica a lápide —
  *"você leu · o texto não existe mais"*.

Tirar o texto no instante da leitura significaria que a mensagem nunca chegou
a ser lida; sumir sem deixar nada faria a conversa parecer que nunca
aconteceu. A lápide vive na aba e só nela: recarregar leva tudo, e no
servidor nunca houve nada para levar.

**"Lida" quer dizer lida.** A confirmação só é enviada quando a mensagem está
de fato à frente da pessoa: conversa aberta e aba em primeiro plano. Uma
mensagem que chega enquanto você está em outro canal fica esperando — conta
como não lida, e uma mensagem de queima não é destruída antes de alguém ter a
chance de lê-la.

## Mensagens de voz

Use **Gravar áudio**, **Parar gravação** e **Enviar áudio**. Antes de enviar,
você pode ouvir a prévia ou **Descartar**. Cada gravação tem limite de
**2 minutos e 512 KiB**; o limite de tamanho pode ser atingido antes dos dois
minutos, dependendo do navegador. Não há transcrição nem serviço externo.

- O microfone só é solicitado após clicar em gravar, em HTTPS ou localhost.
  Ele é desligado ao parar, descartar, trocar de conversa, ocultar a aba,
  desconectar ou sair. Uma captura ainda ativa é descartada ao ocultar a aba.
- Áudio, formato e duração são cifrados no navegador. Cada mensagem tem chave
  própria, envelopada para os mesmos destinatários do texto, inclusive o autor.
- **Queimar ao começar a ouvir** confirma a leitura quando a reprodução
  efetivamente começa, não ao abrir a conversa ou carregar o player. Isso não
  significa que a pessoa ouviu até o fim. A cópia do destinatário é removida
  do servidor; a do autor aguarda todos os destinatários iniciarem a reprodução.
- Depois da queima, o áudio continua disponível nesta conversa até você sair
  dela ou o prazo original acabar. Sair remove a cópia local e deixa a lápide.
  Excluir ou expirar interrompe o player e revoga o URL temporário.
- A aplicação não persiste gravações no navegador. Isso não é uma garantia de
  apagamento físico da memória, dos buffers do navegador ou do sistema operacional.
  Quem recebe pode gravar outra cópia; voz e sons do ambiente também identificam.

Voz usa envelope **v3** com cabeçalho autenticado e padding fixo de 526.336
bytes antes da cifra. O tamanho não revela a duração exata, mas versão, número
de destinatários e tráfego continuam observáveis. O texto mantém compatibilidade
com v2. Recarregue **todos os clientes** após atualizar; clientes antigos não
decifram v3.

O limite padrão do servidor agora é `MAX_ENVELOPE_BYTES=5242880` (5 MiB).
Uma voz custa aproximadamente 0,7 MB no armazenamento **por destinatário**,
mesmo sendo curta. Imagem/PDF de até 4 MiB podem custar cerca de 5 MB por
destinatário após padding. Dimensione memória e retenção para a quantidade
de membros; esta alteração não acrescenta proteção contra abuso por usuários
autorizados.

Testes unitários de voz: `cd server && npm run test:unit`. A suíte `npm test`
também verifica voz em DM/grupo, cifra no Redis, exclusão, queima e expiração.

## Imagens e PDF

Use o clipe, **colar** (Ctrl/Cmd+V) uma imagem ou **arrastar** imagem/PDF para
o compositor. Antes de enviar, há prévia e **Descartar**. Limite de **4 MiB**
por arquivo (JPEG, PNG, WebP, GIF ou PDF). Imagens maiores são redimensionadas
no navegador quando possível. Legenda opcional no campo de texto.

- Tipo, nome, legenda e bytes ficam **dentro da cifra**. Nenhum upload multipart
  em claro; o relay só vê o envelope opaco, como no texto e na voz.
- Visualização usa URLs `blob:` locais (imagem inline + ampliação; PDF com
  preview sob demanda e abertura em nova aba). A CSP autoriza `blob:` em
  `img-src` e `frame-src`.
- **Queima:** imagem confirma leitura com a conversa visível (como texto).
  PDF confirma ao abrir/ver o documento (como o áudio ao começar a ouvir).
- A aplicação não persiste anexos no navegador. Destinatários podem capturar
  a tela ou salvar o arquivo; o servidor esquecer no prazo não impede isso.

Arquivos usam envelope **v4** com AAD e padding em buckets (256 KiB … ~4 MiB).
Clientes antigos não decifram v4 — recarregue todos após atualizar.

## A barra lateral

- **#geral** — o canal de todo mundo, com o número de membros e um contador
  de não lidas.
- **Conversas** — as conversas diretas vivas nesta sessão, ordenadas pela
  última mensagem, com contador de não lidas e horário. A conversa aparece
  sozinha para os dois lados quando a primeira mensagem chega: quem recebe
  não precisa procurar ninguém.
- **Nova conversa** — para começar uma que ainda não existe.

A lista é derivada do que está vivo, não de um histórico guardado. Se todas as
mensagens de uma conversa expirarem e a sessão for reiniciada, ela some da
barra — não há registro de que existiu.

## Identidade e sessão

A identidade é **o nome que você digita ao entrar**. Cada nome tem seu próprio
par de chaves guardado neste navegador; entrar com um nome diferente é ser
outra pessoa, para todos os efeitos — outra impressão digital, outras
mensagens.

Recarregar a página mantém você conectado: a identidade fica em
`sessionStorage`, que morre quando a aba fecha, e as mensagens ainda vivas são
reentregues pelo servidor. Nada disso vai para o disco. Para trocar de
identidade sem fechar a aba, use **Sair desta identidade**.

## Avisos no celular (Web Push)

O Sigilo pode avisar no aparelho quando chegar mensagem, mesmo com a aba em
segundo plano. O payload é só **"Nova mensagem"** — sem remetente nem
prévia. O conteúdo continua vindo pelo WebSocket ao abrir o app.

1. Gere chaves VAPID: `cd server && npx web-push generate-vapid-keys`
2. Coloque `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY` e (opcional)
   `VAPID_SUBJECT` no `.env`
3. No app, abra sua identidade e ative **Avisar no celular**

No iPhone, o Safari só entrega push depois de **Adicionar à Tela de Início**
(PWA). Em HTTPS (não só localhost) e com permissão concedida.

Sem as chaves VAPID o servidor sobe normalmente e o toggle fica oculto.

## Como as pessoas entram

Não há convite nem senha. **Quem alcança a URL e escolhe um identificador
livre está dentro** e já faz parte do `#geral`. O controle de acesso é a rede:
quem consegue chegar ao endereço, entra.

Isso é uma decisão, não um esquecimento — e ela só se sustenta se o endereço
não for público. Publique atrás da VPN da organização, numa tailnet, ou atrás
de um proxy que exija autenticação antes de chegar ao Sigilo.

O que o sistema garante, mesmo com entrada aberta:

- **ninguém toma a identidade de outro.** O primeiro a registrar um
  identificador fica com ele; qualquer chave diferente depois disso é
  recusada (HTTP 409) e só passa com o `ROTATION_TOKEN`, entregue por fora;
- **entrar como você exige o seu dispositivo.** A credencial é a chave
  privada, não uma senha — a conexão só é aceita depois de assinar um desafio;
- **quem entra hoje não lê o que passou ontem.** Não há histórico.

A conferência de impressão digital é o que fecha o resto: ela diz que a pessoa
do outro lado é quem você pensa, independentemente de como ela entrou.

**Fixar não é conferir.** Ao ver alguém pela primeira vez, o cliente fixa a
chave dessa pessoa automaticamente — isso serve para detectar mudanças dali em
diante, e só. O rótulo continua **não verificado** até que um humano compare os
números por outro canal e confirme. Nenhum caminho automático marca alguém como
verificado.

Se a chave de alguém mudar (troca de aparelho, reinstalação, limpeza do
navegador — ou um ataque), essa pessoa é excluída dos seus envios e marcada em
vermelho. Toque no nome dela no painel do canal para conferir a nova impressão
digital e voltar a incluí-la.

Quando chega uma mensagem que não abre — porque quem enviou é novo para você,
ou porque a chave dela mudou — a conferência aparece sozinha, com o nome de
quem enviou. Se você confirmar, a mensagem é aberta na hora: ela continua viva
no servidor até o prazo dela, faltava só a confiança. Se recusar, ela fica
travada e expira sem ser lida.

O elenco se atualiza sozinho: quando alguém entra, todos os clientes
conectados recebem o aviso e recarregam a lista. Ninguém fica com uma lista
velha sem saber.

### Identificadores

O nome digitado é normalizado antes de virar identificador: acentos caem,
maiúsculas viram minúsculas, espaços viram ponto. "João Silva" entra como
`joao.silva`, e a tela mostra isso antes de confirmar. São aceitos letras sem
acento, números, `.`, `-` e `_`, de 2 a 32 caracteres.

Se o identificador já estiver em uso por **outra chave**, a entrada é recusada
(409). Isso é a proteção contra tomada de identidade funcionando — não um bug.
Escolha outro identificador, ou rotacione com o `ROTATION_TOKEN` se o
dispositivo for legitimamente seu.

### Zerando tudo

Não existe `FLUSHDB`: os comandos destrutivos estão desabilitados no
`redis.conf`. Como também não existe persistência, apagar tudo é reiniciar:

```bash
docker compose restart redis server
```

Isso descarta identidades, elenco e mensagens em trânsito. Todo mundo volta a
se registrar do zero.

## Como publicar para o time

O navegador só libera as funções de criptografia em **HTTPS** (ou em
`localhost`). Num endereço `http://192.168.x.x` o Sigilo mostra um aviso e se
recusa a funcionar, em vez de operar sem cifrar. Então "compartilhar o IP da
máquina" não funciona — e não deveria.

**Com domínio próprio** (certificado automático):

```bash
SIGILO_DOMAIN=chat.suaempresa.com docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
```

**Sem domínio, só para o time** — Tailscale resolve nome, certificado e
controle de acesso de uma vez, e o chat fica invisível para a internet:

```bash
tailscale serve --bg 8090
```

O endereço `https://<máquina>.<tailnet>.ts.net` que ele devolve é o que você
passa para as pessoas. Só quem está na tailnet alcança.

### Sem Docker

```bash
cd server && npm install
REDIS_URL=redis://:senha@127.0.0.1:6379 ROTATION_TOKEN=um-token npm run dev
```

### Testes

Suíte ponta a ponta contra servidor e Redis reais. Cria identidades de
verdade, troca mensagens 1:1 e de grupo, e verifica de fora que o texto claro
não existe no Redis:

```bash
cd server && REDIS_URL=redis://:senha@127.0.0.1:6379 ROTATION_TOKEN=um-token npm test
```

No compose, o Redis não é publicado no host — de propósito. As verificações
que precisam olhar dentro do banco são **puladas** (e dizem isso) em vez de
falhar. Para rodar a suíte completa contra o stack em containers, suba com a
sobreposição de teste:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
```

## Como funciona

### O envelope

1. Cada usuário gera dois pares de chaves P-256 no navegador: **ECDH** (acordo
   de chave) e **ECDSA** (prova de identidade). As privadas nascem com
   `extractable: false` — vivem no IndexedDB como `CryptoKey` e nenhum
   JavaScript, nem o desta aplicação, consegue lê-las.
2. Remetente e destinatário derivam o mesmo segredo por ECDH, passam por
   HKDF-SHA256 com salt novo a cada mensagem, e cifram com AES-256-GCM.
3. O texto é preenchido até um bucket fixo (256 / 1024 / 4096 / 16384 bytes)
   antes de cifrar — o tamanho do envelope não conta nada sobre a mensagem.

### O canal geral

Todo mundo que registra uma identidade entra no `#geral`. Não há grupo a
criar nem administrador para gerenciar.

Cada mensagem nasce com uma chave própria (MK) — no canal e na conversa
direta, o formato é o mesmo. O conteúdo é cifrado **uma vez** com ela; a MK é
envelopada **individualmente** para cada destinatário, usando o ECDH do par.
O servidor faz o fan-out de cópias que já vieram prontas — e continua sem
conseguir abrir nenhuma.

**O remetente entra na própria lista de destinatários.** Sem isso ele não
consegue reabrir o que escreveu: a mensagem sumiria da tela dele no primeiro
recarregamento e continuaria viva para todo mundo. Com a cópia, um F5
restaura a conversa inteira dos dois lados, com quem falou o quê.

O que decorre disso:

- não existe "chave do grupo" guardada em lugar nenhum para vazar;
- quem entra depois não alcança nada do que já passou;
- sair do grupo é deixar de receber envelopes — não há chave a revogar;
- um membro cuja chave pública mudou é **excluído do envio pelo cliente**,
  não pelo servidor, e aparece em vermelho no painel do canal. Toque no nome
  para conferir a nova impressão digital e voltar a incluí-lo;
- o envelope cresce cerca de 120 bytes por membro. Para chat interno, é
  irrelevante; para milhares de membros, exigiria repensar (MLS).

Cada cópia tem seu próprio relógio, todos armados no mesmo instante: a
mensagem some para todo mundo quando o prazo acaba, tenha sido lida por
ninguém, por alguns ou por todos.

### O trânsito

```
cliente A ──envelope cifrado──▶ servidor ──2ª cifra──▶ Redis (TTL)
                                    │
                                    └──▶ WebSocket ──▶ cliente B ──▶ "read" ──▶ DEL
```

- **Segunda camada de cifra**: o servidor re-cifra o envelope com uma chave
  gerada no boot que vive só na heap do processo. Um dump do Redis, sozinho,
  não vale nada. Reiniciar o servidor torna ilegível tudo em trânsito — é o
  comportamento desejado.
- **Formato único de envelope** para conversa direta e canal, com uma chave
  por mensagem envelopada para cada destinatário — inclusive para quem enviou.
- **Prazo contado da criação**: `MSG_TTL`. Por padrão, ler não destrói e não
  encurta; deixar sem ler não prolonga. Quem apaga é o Redis, pelo TTL —
  nenhum código precisa lembrar de fazer isso.
- **Queima ao ser lida (opcional, por mensagem)**: o remetente marca *some
  assim que for lida* no compositor. A cópia do destinatário é destruída no
  ato da leitura, e a do remetente quando todos tiverem lido. O prazo continua
  valendo como teto: se ninguém ler, ela expira do mesmo jeito.
- **Exclusão pelo remetente**: apaga todas as cópias na hora, em todas as
  telas. Só quem enviou pode pedir — o servidor usa o remetente da conexão
  autenticada, nunca o que vem no pedido.
- **Metadado de roteamento** (quem falou com quem) fica só na memória do
  processo Node, nunca no Redis. As chaves do Redis são `m:<uuid>` — nada
  nelas correlaciona remetente e destinatário.
- No cliente, mensagens vivem apenas em memória JS. Recarregar a página as
  descarta da tela — e o servidor reentrega o que ainda não expirou, então
  um F5 não perde nada nem revive nada.

### A identidade

- **TOFU com trava**: a primeira chave vista para um identificador é aceita.
  Qualquer chave diferente depois disso é **recusada** (HTTP 409), a menos
  que venha com `ROTATION_TOKEN` entregue fora de banda.
- **Impressão digital de 25 dígitos** derivada das duas chaves públicas,
  exibida para conferência fora do canal. É o único mecanismo que fecha o
  ataque de troca de chave pelo próprio servidor.
- **Login por assinatura**: ao conectar, o servidor manda um desafio de 32
  bytes e o cliente assina com a ECDSA. Sem a chave privada não há sessão.

### O Redis

`redis/redis.conf` desliga RDB e AOF, apaga `KEYS`/`MONITOR`/`CONFIG`/`DEBUG`,
zera o slowlog e o log em arquivo. O compose roda o container `read_only` com
`/data` em tmpfs, sem swap (`memswap_limit == mem_limit`) e sem core dump.
Nada toca o disco.

## Configuração

Prazos aceitam **s**, **m**, **h**, **d** — `45s`, `10m`, `2h`, `1d`. Número
sem unidade é lido como segundos.

| variável | padrão | o que faz |
|---|---|---|
| `REDIS_URL` | `redis://127.0.0.1:6379` | conexão com o Redis |
| `ROTATION_TOKEN` | — (obrigatório) | autoriza troca de chave de um usuário |
| `MSG_TTL` | `1d` | vida da mensagem, contada da criação |
| `MSG_TTL_MIN` | `30s` | piso: o remetente não consegue pedir menos |
| `MSG_TTL_MAX` | `7d` | teto: o remetente não consegue pedir mais |
| `TTL_OPTIONS` | `5m,1h,8h,1d,3d,7d` | opções do seletor na interface |
| `MAX_ENVELOPE_BYTES` | `5242880` | teto de tamanho do envelope (5 MiB; voz, imagem e PDF) |

O remetente escolhe o prazo **por mensagem** no seletor ao lado do campo de
texto. O servidor valida cada pedido contra o piso e o teto acima — quem
manda no limite é a instalação, não o cliente.

## Antes de usar para valer

Leia **[SECURITY.md](SECURITY.md)**. Ele diz o que esta arquitetura garante,
o que ela só mitiga, e o que ela não pode garantir de jeito nenhum.

Pendências conhecidas para produção:

- Registro de chaves públicas está no Redis (some se o Redis reiniciar).
  Em produção isso pertence ao Postgres — é o único dado durável do sistema.
- Sem forward secrecy: o ECDH é estático. A evolução é Double Ratchet
  (libsignal) ou MLS.
- O canal geral usa fan-out no envio (uma cópia por membro). Isso escala bem
  até a casa das dezenas; acima disso, MLS é o caminho.
- O roteamento em memória é de instância única. Escalar horizontalmente
  exige mover o metadado para o Redis — com o custo de privacidade que isso
  implica.
