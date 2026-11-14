# Monitorização de Saúde Espacial

Backend inicial para registar e consultar indicadores de saúde de astronautas,
usando Python, FastAPI e SQLite.

## Executar localmente

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
$env:PYTHONPATH = "backend"
uvicorn app.main:app --reload --app-dir backend
```

A documentação interativa da API fica disponível em `http://127.0.0.1:8000/docs`.
Por omissão, a base de dados é criada em `data/health_monitoring.sqlite3`.
Define `HEALTH_DB_PATH` para escolher outro caminho.

## Endpoints implementados

- `GET /health` — estado do serviço.
- `GET /api/v1/indicators` — indicadores, unidades e limites técnicos de entrada.
- `POST /api/v1/readings` — regista um conjunto de medições com o mesmo instante
  (token de utilizador com `readings:write` e escopo para o astronauta).
- `GET /api/v1/readings` — consulta histórico por astronauta, indicador e período,
  com paginação (token de utilizador com `readings:read` e escopo para o
  astronauta).
- `GET /api/v1/readings/analysis` — estatísticas descritivas e inclinação linear
  por dia para um indicador, astronauta e intervalo definidos (requer contexto
  explícito para glicemia; token de utilizador com `readings:read`).
- `POST /api/v1/sync/readings` — recebe um lote offline limitado e idempotente,
  devolvendo confirmação por medição (token de dispositivo com `sync:write`,
  identidade igual a `source_device_id` e escopo para os astronautas do lote).
- `GET /api/v1/sync/batches/{batch_id}` — consulta o recibo persistido de um lote
  (apenas o mesmo dispositivo autenticado).

### Exemplo de registo

```json
{
  "astronaut_id": "astronaut-01",
  "measured_at": "2026-11-14T16:00:00Z",
  "measurements": [
    {"metric": "systolic_blood_pressure", "value": 120},
    {"metric": "diastolic_blood_pressure", "value": 80},
    {"metric": "heart_rate", "value": 72},
    {"metric": "blood_glucose", "value": 95.5},
    {"metric": "body_temperature", "value": 36.8},
    {"metric": "sleep_duration", "value": 7.5},
    {"metric": "mood", "value": 4},
    {"metric": "blood_oxygen", "value": 98}
  ],
  "glucose_context": "fasting"
}
```

Os indicadores e unidades têm nomes canónicos na API. Os dados devem incluir
datas com fuso horário; são normalizados para UTC. Glicemia aceita o contexto
`fasting`, `after_meal`, `random` ou `unknown`. Pressão arterial exige os dois
valores e valida que a diastólica é inferior à sistólica.

Os limites expostos são validações técnicas das entradas, não intervalos de
normalidade, diagnósticos ou critérios de aptidão médica.

A análise devolve quantidade, mínimo, máximo, média, mediana, desvio-padrão
amostral, última medição e inclinação linear por dia. `start` e `end` são
obrigatórios e devem incluir fuso horário. Para glicemia, `glucose_context`
também é obrigatório para evitar misturar contextos de medição. A inclinação e
as estatísticas são descritivas; não identificam anomalias nem substituem
avaliação clínica. O endpoint não descarta valores silenciosamente; corrupção
ou valores não finitos persistidos impedem a análise.

## Autenticação e autorização

Os endpoints protegidos exigem um JWT RS256 emitido pelo serviço de identidade
local da missão. A configuração de confiança chega por um caminho absoluto
definido em `MISSION_BOOTSTRAP_PATH`, que aponta para um ficheiro JSON com:

- `base_configuration`: missão, autoridade terrestre e identidades provisionadas,
  sem delegações não verificadas;
- `ground_keys`: emissor, `kid`s confiáveis e chaves públicas RSA terrestres;
- `onboard_token_verifier`: `key_id`, chave pública RSA do serviço a bordo e
  `audience`;
- `initial_signed_delegation_tokens`: delegações JWT RS256 assinadas pela Terra,
  usadas apenas para o provisionamento inicial.

A chave pública onboard tem de corresponder ao `key_id` e a impressão digital
`sha256:<SHA-256 do SubjectPublicKeyInfo DER>` da identidade do serviço a bordo.
O ficheiro não pode conter chaves privadas. Em POSIX, deve pertencer ao
utilizador do serviço e ter modo `0600`; em Windows, o proprietário deve ser a
conta do serviço e as ACEs so podem conceder acesso a essa conta, `SYSTEM`,
Administrators ou `OWNER RIGHTS`. O carregador rejeita links/reparse points,
ficheiros maiores que 1 MiB e ACLs/permissões excessivas.

Exemplo de inicialização em PowerShell:

```powershell
$env:MISSION_BOOTSTRAP_PATH = "C:\secure\mission-bootstrap.json"
$env:HEALTH_DB_PATH = "C:\secure\health_monitoring.sqlite3"
$env:PYTHONPATH = "backend"
uvicorn app.main:app --app-dir backend
```

O emissor local assina tokens com `kid` igual a chave onboard provisionada. Os
tokens devem conter `sub`, `iss` (ID do serviço onboard), `aud`, `iat`, `nbf`,
`exp`, `jti`, `mission_id`, `actor_type`, `astronaut_ids` e `permissions`. A cada
pedido protegido, a API valida novamente as delegações persistidas e exige que
a missão, o serviço, a identidade individual, o tipo de ator, o período do
token, escopos e permissões estejam ativos e cobertos pela delegacao. A
identidade de dispositivo também tem de corresponder a `source_device_id`.
Ficheiro de bootstrap ausente deixa rotas protegidas fechadas (503); se estiver
configurado mas inválido ou a delegacao persistida for inválida, a API não
inicia.

O primeiro conjunto de delegações e instalado na base SQLite apenas se ainda
não existir provisionamento para a missão. Um bootstrap atualizado não
substitui automaticamente delegações persistidas; ainda falta um canal/CLI
administrativo autenticado para atualizar e revogar a configuração em operação.
O `OnboardTokenService` implementa emissão, rotação de refresh tokens e
revogação local por família, mas ainda não existe endpoint HTTP nem uma
fronteira de autenticação offline para comprovar a identidade de utilizadores
ou dispositivos antes da emissão. Tokens de acesso requerem `jti` e registo
persistido; cada pedido protegido consulta o estado de revogação. A chave
privada onboard tem de ser fornecida em runtime e não é guardada no bootstrap
nem na base de dados. Ainda faltam um provedor seguro dessa chave, registo/login,
prova de posse de dispositivo e protocolo de rotação de chaves. A base SQLite
não protege contra rollback ou adulteração por um administrador local. Não usar
dados reais nem expor a rede antes de validar o provisionamento no ambiente de
missão, a política temporal, transporte TLS/mTLS e os controlos operacionais.

## Sincronização offline (interface do backend)

O cliente offline deve guardar cada medição numa fila local durável antes de a
considerar gravada. Cada medição enviada precisa de um `reading_id` UUID criado
no dispositivo; cada medição tem um `sequence_number` crescente, único por
dispositivo. Cada lote inclui um `batch_id` e `source_device_id` UUID. O endpoint
aceita até 100 medições por lote. Pode reenviar o mesmo lote após timeout: o
recibo original é devolvido sem criar duplicados. Um novo lote que contenha
medições já persistidas recebe `already_received`; reutilizar `batch_id` ou
`reading_id` com conteúdo diferente, ou uma sequência já usada com outra
medição, resulta em `409 Conflict`. O lote, o recibo e as medições são gravados
na mesma transação; se houver conflito, nenhum deles é confirmado. O cliente só
deve retirar da fila as medições explicitamente confirmadas depois da resposta
bem-sucedida; deve manter o lote para repetição após timeout, desconexão ou erro.

Após timeout ou perda da resposta, o dispositivo pode consultar
`GET /api/v1/sync/batches/{batch_id}` com o mesmo token de dispositivo. O estado
`persisted` e a lista de medições significam que esse lote foi confirmado no
serviço local; um lote ainda não persistido responde `404`. As medições de um
lote rejeitado por conflito não têm recibo parcial.

Exemplo do corpo para sincronização:

```json
{
  "batch_id": "c54d86ca-59f9-41b6-9dbb-f18b3976fc31",
  "source_device_id": "99d52a98-95e3-48ae-a0c2-24d888d1183f",
  "readings": [
    {
      "astronaut_id": "astronaut-01",
      "measured_at": "2026-11-14T16:00:00Z",
      "measurements": [
        {
          "reading_id": "f59b83f0-56a8-47f3-874d-ed940f65d346",
          "sequence_number": 12,
          "metric": "heart_rate",
          "value": 72
        }
      ]
    }
  ]
}
```

Uma resposta `accepted` ou `already_received` confirma a medição indicada por
`reading_id` e sequência; o lote em si só é confirmado quando todas as suas
medições são guardadas e a resposta é enviada.

Esta interface não implementa a fila local da PWA, provisionamento de identidades,
emissão de credenciais, cifragem em repouso nem resolução de sincronização entre
múltiplas fontes. Os UUIDs de dispositivo e identificadores enviados pelo cliente
são metadados; a identidade do dispositivo é verificada pelo token assinado.
Autenticação e autorização atuais são apenas validação stateless de claims. A
migração SQLite adiciona as colunas de sincronização e tabelas de recibos sem
apagar os registos existentes. As gravações locais usam transações SQLite,
chaves estrangeiras e `synchronous=FULL`; a durabilidade ainda depende do
armazenamento e da plataforma reais e precisa de validação de falhas. Este
backend não retransmite para o sistema terrestre. O modo offline ainda não foi
validado para operação espacial: requer testes de perda de ligação/reinício e
revisão de segurança e missão antes de dados reais.

## Modelos de identidade da missão

Os modelos iniciais de missão, identidade e delegação estão em
`backend/app/mission_identity.py`. Validam relações, missão, referências de
chaves, escopos/permissões máximos e consistência temporal. Os tempos da
delegação e a duração máxima dos tokens são obrigatórios, sem defaults, porque
a política operacional ainda não foi decidida. Estes modelos não implementam
provisionamento, persistência de identidades, gestão de chaves nem emissão de
credenciais.

### Verificação da delegação terrestre

`backend/app/key_management.py` valida delegações JWT assinadas pela autoridade
terrestre. A configuração (`VerificationKeySet`) tem de ser provisionada com o
emissor e o conjunto explícito de `kid` confiáveis; cada chave contém apenas a
chave pública PEM RSA (mínimo 2048 bits), finalidade e períodos explícitos de
validade. A chave privada terrestre não deve ser distribuída ao serviço a bordo,
e o `kid` nunca é usado para procurar chaves numa URL ou fonte indicada pelo
token.

O formato aceite é restrito:

- Cabeçalho: exatamente `alg: RS256`, `kid` e `typ: mission-delegation+jwt`.
- Claims: exatamente `iss`, `aud`, `iat`, `nbf`, `exp`, `jti` e `delegation`.
- `aud` identifica o serviço a bordo esperado; `jti` corresponde ao UUID da
  delegação. As datas NumericDate têm de corresponder aos instantes da delegação.
- O verificador confere a assinatura, emissor, audiência, validade temporal da
  delegação e janelas da chave, além dos identificadores esperados de missão e
  serviço a bordo. A validação cruzada de validade, escopo e permissões entre
  missão, serviço e delegação é feita por `MissionIdentityConfiguration` e
  ainda não é invocada automaticamente pelo verificador.

A suite cobre assinatura válida/adulterada, chave desconhecida ou revogada,
rotação com chave retirada, cabeçalhos e claims não permitidos e datas e
relações inválidas. `load_signed_mission_identity_configuration()` recebe uma
configuração-base sem delegações, os JWTs assinados e o conjunto de chaves
provisionadas. Rejeita autoridade/chaves divergentes, missão inativa ou fora da
validade, serviço a bordo não provisionado, delegações pré-carregadas sem prova
criptográfica e delegações que excedam a missão, o serviço, os escopos ou as
permissões. O resultado é uma configuração imutável validada.

O verificador e o carregador de configuração estão ligados ao arranque e à
autorização da API por meio do bootstrap descrito acima. Ainda não emite
credenciais. A rotação de chaves, revogação sincronizada e políticas temporais
operacionais continuam por definir e validar. Isto não constitui prontidão para
uso com dados reais ou em missão.

### Persistência do provisionamento

`backend/app/provisioning.py` instala e recarrega delegações assinadas na tabela
`provisioned_mission_delegations`. O instalador verifica o conjunto completo
antes de substituir o registo existente, numa transação SQLite; no arranque e
em cada pedido protegido, os JWTs persistidos são novamente verificados com a
configuração-base da missão e o conjunto de chaves confiáveis fornecidos
localmente. A base de configuração e as chaves públicas de confiança não são
aceites do conteúdo persistido.

Esta tabela guarda os JWTs assinados, não os torna confidenciais nem protege
contra adulteração/rollback do ficheiro SQLite. A chave pública raiz e a base
da missão precisam de ser provisionadas por um canal local protegido; cifragem
em repouso, controlo de rollback, auditoria e canal administrativo para atualizar
ou revogar delegações permanecem por implementar. A persistência SQLite, por si
só, não é uma fronteira de segurança para operação de missão.

## Arquitetura offline

A decisão sobre responsabilidades, propriedade dos dados, fluxo entre
dispositivo/PWA, serviço a bordo e sistema terrestre, estados por salto,
confirmações e tratamento de falhas está documentada em
[Arquitetura de dados e sincronização offline](docs/architecture/offline-data-synchronization.md).
Esse documento define a arquitetura pretendida; não significa que a fila offline
ou os controlos de missão já estejam implementados.

## Testes

```powershell
$env:PYTHONPATH = "backend"
python -m pytest backend\tests
```
