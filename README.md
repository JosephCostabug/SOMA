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
- `POST /api/v1/readings` — regista um conjunto de medições com o mesmo instante.
- `GET /api/v1/readings` — consulta histórico por astronauta, indicador e período,
  com paginação.
- `POST /api/v1/sync/readings` — recebe um lote offline limitado e idempotente,
  devolvendo confirmação por medição.

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
normalidade, diagnósticos ou critérios de aptidão médica. Este protótipo ainda
não implementa autenticação/autorização: não deve ser exposto a dados reais ou
a redes públicas antes de acrescentar esses controlos e rever a segurança.

## Sincronização offline (interface do backend)

O cliente offline deve guardar cada medição numa fila local durável antes de a
considerar gravada. Cada medição enviada precisa de um `reading_id` UUID criado
no dispositivo; cada medição tem um `sequence_number` crescente, único por
dispositivo. Cada lote inclui um `batch_id` e `source_device_id` UUID. O endpoint
aceita até 100 medições por lote. Pode reenviar o mesmo lote após timeout: a
mesma medição é confirmada como `already_received`, sem criar duplicados;
reutilizar um ID com conteúdo diferente ou uma sequência já usada com outra
medição resulta em `409 Conflict`. O lote é gravado numa transação: se houver
conflito, nada desse lote é confirmado. O cliente só deve retirar da fila as
medições explicitamente confirmadas depois da resposta bem-sucedida; deve manter
o lote para repetição após timeout, desconexão ou erro.

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

Esta interface não implementa a fila local da PWA, autenticação de dispositivos,
autorização, cifragem em repouso nem resolução de sincronização entre múltiplas
fontes. Os UUIDs de dispositivo e identificadores enviados pelo cliente são
metadados, não prova de identidade. A migração SQLite adiciona as colunas de
sincronização sem apagar os registos existentes. O modo offline ainda não foi
validado para operação espacial: requer testes de perda de ligação/reinício e
revisão de segurança e missão antes de dados reais.

## Testes

```powershell
$env:PYTHONPATH = "backend"
python -m pytest backend\tests
```
