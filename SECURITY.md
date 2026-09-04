# Modelo de ameaça do Sigilo

Este documento diz o que a arquitetura garante, o que ela apenas mitiga, e o
que ela não pode garantir. A terceira lista é a mais importante — um sistema
de privacidade que promete demais é pior que um que promete pouco, porque as
pessoas ajustam o comportamento pelo que acreditam.

## Garantido pela arquitetura

Não são configurações que alguém pode esquecer de ligar: são consequências de
como o sistema foi montado.

**O servidor não consegue ler as mensagens.** A chave de decifra nasce e morre
no dispositivo, com `extractable: false`. Nem o operador do servidor, nem
quem obtiver acesso de root a ele, nem uma intimação judicial dirigida a
quem hospeda extraem conteúdo — não existe onde buscar.

**Nada toca o disco.** RDB e AOF desligados, `/data` em tmpfs, sem swap, sem
core dump, sem slowlog, sem log em arquivo. Não há artefato para perícia
recuperar depois.

**Exclusão e queima destroem de verdade.** Apagar uma mensagem, ou lê-la
quando o remetente pediu queima, remove o registro do Redis — não marca como
oculto. O que fica é o que já foi lido pelas pessoas, que nenhum sistema
alcança.

**A mensagem morre no prazo, e o prazo é do Redis.** O TTL é armado na criação
e nada o altera depois: ler não encurta, ignorar não prolonga, e nenhum código
precisa lembrar de apagar. Se o processo cair, se o servidor for reiniciado,
se ninguém nunca mais conectar — a mensagem some do mesmo jeito, na hora
combinada.

**Um dump do Redis não vale nada sozinho.** A segunda camada de cifra usa uma
chave gerada no boot que só existe na heap do processo Node. Quem levar o
Redis leva ruído.

**O grafo social não está no banco.** Quem falou com quem vive apenas na
memória do processo, pelo tempo de vida da mensagem. As chaves do Redis são
UUIDs sem dono.

**O tamanho não fala.** Padding para buckets fixos antes de cifrar.

**Ninguém se passa por outro.** Entrar exige assinar um desafio de 32 bytes
com a chave privada ECDSA. Sem o dispositivo, não há sessão.

**O servidor não consegue trocar uma chave em silêncio.** Uma chave nova para
um identificador conhecido é recusada com HTTP 409. Rotação legítima exige um
token entregue por fora. No cliente, uma chave que mudou trava a conversa e
exige confirmação humana da impressão digital.

**No canal geral, o servidor não escolhe quem recebe.** Cada mensagem tem
chave própria, envelopada individualmente pelo remetente para cada membro.
O servidor só distribui as cópias que o remetente já preparou — e não abre
nenhuma. Quem entra depois não alcança o que já passou.

## Mitigado, não eliminado

**O servidor entrega o JavaScript.** Este é o calcanhar de Aquiles de todo
E2EE web: quem controla o deploy pode servir um bundle que exfiltra a chave.

Aqui: CSP sem `unsafe-inline`, zero CDN, zero dependência de terceiros no
cliente, todo o código em dois arquivos legíveis. Isso reduz a superfície,
mas não elimina o problema.

*Para fechar de verdade:* empacotar como aplicativo nativo ou extensão de
navegador — código instalado uma vez e assinado, não rebaixado a cada visita.
Alternativa web: build reprodutível com o hash publicado num log de
transparência, mais uma extensão que confira o que foi servido. O resultado
não é "impossível atacar", é "impossível atacar sem deixar prova pública".

**Metadados de tráfego.** O servidor não guarda o grafo social, mas observa
conexões em tempo real: quem está online, quando envia, com que frequência.
Mitigado por sealed sender parcial e padding; eliminar exigiria tráfego de
cobertura constante. Web Push, se ativado pelo destinatário, adiciona um
sinal de timing ao serviço de push do navegador (FCM/Mozilla/Apple): o
payload permanece genérico ("Nova mensagem"), sem remetente nem conteúdo.

**Sem forward secrecy.** O ECDH é estático. Comprometer a chave privada de um
dispositivo abre as mensagens que ainda estiverem dentro do prazo para ele —
não as já expiradas, que não existem mais em lugar nenhum. Prazos mais curtos
reduzem essa janela; é a razão prática para não deixar tudo em 7 dias. A evolução natural é
Double Ratchet (libsignal) ou MLS.

**Confiança na primeira visão.** TOFU protege contra troca de chave depois do
primeiro contato, não contra um servidor malicioso já no primeiro. Só a
conferência da impressão digital fora de banda fecha isso — e no canal geral,
membros novos entram marcados como não verificados justamente por isso.

## Não garantido — e não há como garantir

### Mensagens de voz

Voz segue o mesmo modelo de confiança do texto: ECDH/HKDF e AES-256-GCM,
chave nova por mensagem, envelopes individuais, TTL e exclusão no relay.
O envelope v3 autentica também versão, remetente e destino como AAD. Tipo,
codec, duração e bytes de áudio ficam dentro da cifra. A gravação é limitada
a 2 minutos / 512 KiB e preenchida até um tamanho fixo antes de cifrar;
a versão permite distinguir voz de texto e o tráfego continua observável.

Não há serviço de transcrição, analytics ou upload de mídia em claro.
A reprodução usa somente URLs `blob:` locais, autorizados pela CSP, com
revogação ao excluir, expirar, sair da conversa ou destruir a mensagem.
O microfone é desligado ao parar/cancelar e nas transições de saída ou ocultação
da aba. O recebimento de voz não confirma leitura: só o início efetivo da
reprodução o faz. Essa confirmação **não comprova escuta integral**.

Não prometemos que nenhum byte tocará disco no dispositivo: o navegador e o
sistema operacional controlam buffers, swap e recuperação de sessão. Zerar
arrays e revogar URLs libera referências da aplicação, não comprova apagamento
forense. A configuração de Redis sem persistência continua necessária no servidor.
Identidades e pins, ao contrário das gravações, já são persistidos em IndexedDB.

A voz pode identificar o falante; ruídos podem revelar ambiente e terceiros.
Destinatários podem gravar a reprodução. As limitações de E2EE web e a ausência
de forward secrecy também permanecem. Maior tamanho aumenta custo de memória
e risco de indisponibilidade: cada destinatário recebe uma cópia cifrada de
cerca de 0,7 MB, e não há rate limiting ou quota por usuário nesta implementação.

### Imagens e PDF

Anexos seguem o mesmo modelo: ECDH/HKDF e AES-256-GCM, chave nova por mensagem,
envelopes individuais, TTL e exclusão no relay. O envelope **v4** autentica
versão, remetente e destino como AAD. Tipo (`imagem` | `pdf`), MIME, nome,
legenda e bytes ficam dentro da cifra. O payload é limitado a 4 MiB e preenchido
até um dos buckets fixos antes de cifrar; o tamanho aproximado ainda vaza pelo
bucket e pelo tráfego.

Não há upload de mídia em claro, CDN nem visualizador de terceiros. Preview e
ampliação usam somente URLs `blob:` locais (`img-src` / `frame-src` na CSP),
com revogação ao excluir, expirar, sair da conversa ou destruir a mensagem.
SVG é recusado. A assinatura do arquivo (magic bytes) precisa bater com o MIME.

Imagem confirma leitura como texto (conversa visível). PDF só confirma ao
abrir/ver o documento — preview embutido não carrega sozinho. Destinatários
podem capturar a tela ou guardar o blob. Maior tamanho aumenta custo de memória
no Redis (até ~5 MiB cifrado por destinatário) e risco de indisponibilidade.

### Limites gerais

**O destinatário reter a mensagem.** Print de tela, foto do monitor com o
celular, cliente modificado, OCR. Uma vez que o texto claro chega ao
dispositivo da outra pessoa, ele é dela. Nenhum TTL muda isso; DRM não
resolve, apenas eleva o custo do ataque de zero para quinze segundos.

O que o Sigilo garante é que o *servidor* esquece, no prazo escolhido — e
que a mensagem some da tela de todo mundo naquele instante. Não que o
destinatário esqueceu. A interface deve dizer "a mensagem some daqui",
nunca "a mensagem é impossível de guardar".

**Um dispositivo comprometido.** Keylogger, malware, tela espelhada, alguém
lendo por cima do ombro. A criptografia termina onde a tela começa.

**Quem já está dentro.** Um membro legítimo do canal geral pode copiar e
repassar tudo que recebe. O canal é aberto a todos os registrados — por
desenho. Se um assunto não pode ser lido por todo mundo da organização, ele
não pertence ao `#geral`.

**Coação.** Nada aqui protege alguém obrigado a desbloquear o próprio
dispositivo.
