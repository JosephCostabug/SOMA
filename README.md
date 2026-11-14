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

## Autenticação e autorização

Os endpoints de leitura, escrita e sincronização exigem um JWT Bearer assinado
com RS256 por um emissor local confiável. Configura o serviço com
`AUTH_PUBLIC_KEY`, `AUTH_ISSUER` e `AUTH_AUDIENCE`; sem estas configurações, os
endpoints protegidos falham de forma fechada. `AUTH_PUBLIC_KEY` deve conter a
chave pública PEM do emissor (em ambientes que não aceitam quebras de linha,
usa `\n` escapado).

O token tem de incluir `sub`, `iss`, `aud`, `iat`, `exp`, `actor_type`,
`astronaut_ids` e `permissions`. `actor_type` é `user` ou `device`. Utilizadores
precisam de `readings:read` e/ou `readings:write`; dispositivos precisam de
`sync:write`, e o `sub` do token de dispositivo tem de corresponder ao
`source_device_id` do lote. A autorização também confere que cada astronauta
está em `astronaut_ids`.

O emissor local da missão é responsável por provisionar identidades e emitir
tokens assinados que funcionem durante a desconexão da Terra. Esta API valida
tokens offline, mas **não** implementa registo de contas, login, emissão ou
renovação de tokens, revogação local ou rotação coordenada de chaves. A
identidade de teste usada pela suite não é uma chave de desenvolvimento nem
deve ser reutilizada. Não usar dados reais nem expor a rede antes de integrar
um emissor confiável, proteger a distribuição da chave pública e validar a
política de validade/revogação dos tokens e o transporte seguro.

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
