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
O painel web fica disponível em `http://127.0.0.1:8000/`.
Por omissão, a base de dados é criada em `data/health_monitoring.sqlite3`.
Define `HEALTH_DB_PATH` para escolher outro caminho.

## Visão operativa do painel

O painel expõe uma visão de missão em etapas: catálogo de indicadores por sistema
corporal, suporte à tendência, aviso explícito de natureza ilustrativa e resumo de
operação/apoio ao solo para manter o contexto do tripulante sem confundir limites
técnicos com interpretação clínica. A continuidade offline continua a ser um
estado de sincronização e apoio local, não uma decisão clínica.

## Etapas priorizadas do produto

1. Base operacional: autenticação, permissões, leitura e registro de medições.
2. Catálogo de indicadores e contexto de missão: sistema corporal, tendência, apoio ao solo.
3. Painel autenticado por astronauta: medições recentes, tendências descritivas,
   cobertura observada, alertas por período e confirmação de receção.
   Implementado; requer token já emitido pela autoridade da missão e ainda
   precisa de validação ponta a ponta.
4. Fila local IndexedDB e sincronização manual pelo endpoint v1. Implementado
   como protótipo; não tem cifragem local nem reconciliação terrestre na interface.
5. Validação de UX, acessibilidade, testes end-to-end e readiness para operação.
   Pendente; não declarar pronto para dados reais ou uso em missão.

## Painel web

O ecrã inicial é o painel da missão: apresenta a figura humana esquemática,
sistemas corporais, formulário de acesso, medições observadas, tendência
descritiva e alertas. O mapa corporal é apenas uma forma de navegar pelo
catálogo; não representa anatomia clínica nem localiza medições no corpo. A
interface não apresenta fontes ou créditos dos conjuntos de dados nem páginas
de documentação; estes detalhes e a proveniência científica ficam neste README.
Alertas podem manter referências de protocolos aprovados para garantir
rastreabilidade operacional.

O endpoint público de dados científicos NASA continua disponível pela API,
mas não é carregado no ecrã inicial. O conjunto OSD-575 (Inspiration4) contém
resultados séricos agregados e não deve ser confundido com medições em tempo
real ou dados operacionais dos tripulantes. A aplicação não guarda o CSV nem
converte estes resultados em medições de astronautas, sinais vitais, alertas ou
limites clínicos. A licença específica do ficheiro não está confirmada;
consulte a citação, versão e termos oficiais antes de reutilizar ou redistribuir.
Crédito de origem: “Data are courtesy of the NASA Open Science Data Repository
(OSDR).” Consulte o [estudo OSD-575](https://osdr.nasa.gov/bio/repo/data/studies/OSD-575)
e as [orientações de citação do OSDR](https://science.nasa.gov/reference/osdr-faq/)
para a citação versionada e os termos aplicáveis.

O deploy de demonstração no Vercel usa o entrypoint Python em `main.py`.
Como o SQLite em `/tmp` não é persistente e o ambiente publicado não tem
bootstrap de missão, este deploy serve apenas as rotas públicas; não use para
guardar nem consultar dados reais de saúde.

O painel requer um token de utilizador emitido pela autoridade de identidade
configurada, com escopos para o astronauta e permissão `readings:read`. A
confirmação de alertas também requer `alerts:acknowledge`.
O token é mantido apenas em memória durante o acesso, pode ser removido pelo
botão “Terminar acesso” e não é guardado em armazenamento do navegador. O painel
exibe medições recentes, contagens observadas e alertas já persistidos; não
calcula diagnóstico nem presume cadência de recolha. Confirmar um alerta só
regista receção, não resolução.
A análise de tendência chama a API descritiva existente; para glicemia, é
obrigatório escolher contexto. A inclinação, média e restantes estatísticas não
são interpretação clínica.

## Backup da base de dados

Cria uma cópia consistente mesmo enquanto a aplicação está ativa, valida
`integrity_check` e chaves estrangeiras, e recusa substituir um destino
existente:

```powershell
$env:PYTHONPATH = "backend"
python -m app.backup --destination "D:\secure-backups\health-2026-11-14.sqlite3"
```

Por omissão, a origem é `HEALTH_DB_PATH`; `--source` permite indicar outra
SQLite. O destino tem de estar numa pasta já existente. Guarde backups apenas em
armazenamento aprovado, com ACL restritiva e cifragem adequada: a cópia contém
dados de saúde e herda as permissões da pasta de destino. O comando não apaga,
nem substitui ficheiros existentes.

Para validar/restaurar uma cópia para um ficheiro novo, sem tocar na base ativa:

```powershell
python -m app.backup --restore `
  --source "D:\secure-backups\health-2026-11-14.sqlite3" `
  --destination "D:\restore-tests\health-restored.sqlite3"
```

Tanto a origem como o destino são verificados com `integrity_check` e
`foreign_key_check`. Isto não define retenção nem garante objetivos de
recuperação; restaurações periódicas e medidas de RPO/RTO continuam necessárias.

## Endpoints implementados

- `GET /health` — estado do serviço.
- `GET /ready` — readiness operacional; requer bootstrap da missão e esquema
  SQLite acessível.
- `POST /api/v1/auth/challenges` — cria desafio de autenticação offline para
  identidade de utilizador/dispositivo com chave pública provisionada.
- `POST /api/v1/auth/token` — troca uma prova RS256 de posse do desafio por
  credenciais limitadas pela identidade e delegação da missão.
- `POST /api/v1/auth/refresh` — roda um refresh token de uso único.
- `POST /api/v1/auth/revoke` — revoga a família associada ao refresh token.
- `GET /api/v1/indicators` — indicadores, nomes legíveis para UI (`display_name`), ordem estável para renderização (`sort_order`), unidades, limites técnicos de entrada, sistema corporal (cardiovascular, metabólico, recuperação, bem-estar, respiratório, termorregulação), suporte a tendência e limiares clínicos marcados como ilustrativos; não constituem diagnóstico nem critério de aptidão e têm referência explícita ao facto de não haver fonte clínica validada neste deployment.
- `GET /api/v1/scientific-data/public/osdr/inspiration4/cmp` — resumo agregado
  dos dados do ficheiro público CMP do estudo NASA OSD-575; não requer login,
  não inclui identificadores de amostra e não alimenta leituras/alertas.
- `POST /api/v1/scientific-data/osdr/studies/{accession}/refresh` — consulta e
  guarda somente metadados públicos do NASA OSDR (requer
  `scientific-data:sync` explicitamente delegado).
- `GET /api/v1/scientific-data/osdr/studies/{accession}` — lê os metadados
  previamente guardados, sem depender de conectividade externa (requer
  `scientific-data:read` explicitamente delegado).
- `POST /api/v1/readings` — regista um conjunto de medições com o mesmo instante
  (token de utilizador com `readings:write` e escopo para o astronauta).
- `GET /api/v1/readings` — consulta histórico por astronauta, indicador e período,
  com paginação (token de utilizador com `readings:read` e escopo para o
  astronauta).
- `GET /api/v1/readings/analysis` — estatísticas descritivas e inclinação linear
  por dia para um indicador, astronauta e intervalo definidos (requer contexto
  explícito para glicemia; token de utilizador com `readings:read`).
- `GET /api/v1/readings/coverage` — contagem observada e instante da última
  medição de cada indicador num intervalo (token de utilizador com
  `readings:read`).
- `GET /api/v1/readings/operations-summary` — resumo por astronauta e período
  com registos válidos, rejeitados, duplicados, conflitos, última recepção e
  origem declarada (token de utilizador com `readings:read`).
- `GET /api/v1/alerts` — histórico paginado de alertas de monitorização por
  astronauta e período (token de utilizador com `readings:read`).
- `POST /api/v1/alerts/{alert_id}/acknowledge` — regista confirmação de receção
  idempotente por utilizador (token com `alerts:acknowledge` e escopo para o
  astronauta; não fecha nem resolve o alerta).
- `GET /api/v1/alerts/rules` — lista regras e estado (token de utilizador com
  `alerts:configure` e escopo sobre todos os astronautas da missão; suporta
  paginação).
- `PUT /api/v1/alerts/rules/{rule_id}` — cria ou atualiza uma regra com controlo
  de versão (mesma autorização; inicia a versão inativa e não aprovada).
- `POST /api/v1/alerts/rules/{rule_id}/approve` — regista aprovação e âmbito
  (token de utilizador com `alerts:approve` e escopo sobre toda a missão).
- `POST /api/v1/alerts/rules/{rule_id}/activate` — ativa apenas uma versão com
  aprovação operacional válida (mesma autorização de configuração).
- `POST /api/v1/alerts/rules/{rule_id}/deactivate` — desativa uma regra sem
  apagar o histórico (mesma autorização).
- `GET /api/v1/alerts/rules/audit` — consulta paginada das alterações e estados
  anteriores/atuais (mesma autorização).
- `POST /api/v1/sync/readings` — recebe um lote offline limitado e idempotente,
  devolvendo confirmação por medição (token de dispositivo com `sync:write`,
  identidade igual a `source_device_id` e escopo para os astronautas do lote).
- `POST /api/v2/sync/readings` — mesmo contrato de receção local, com
  `earth_sync_eligible` obrigatório em cada medição e criação transacional da
  outbox terrestre para novas medições opt-in.
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

## Alertas de monitorização

Não há limiares clínicos predefinidos. Para ativar alertas, o bootstrap pode
incluir `monitoring_alert_rules`, uma lista de regras com `rule_id`, `version`,
`metric`, `minimum_value` e/ou `maximum_value`, `rationale` e
`source_reference`. Os limites configurados são inclusivos: um evento é criado
apenas quando uma medição fica estritamente abaixo do mínimo ou acima do máximo.
Os valores têm de ser finitos e estar dentro dos limites técnicos de entrada do
indicador; esses limites técnicos não são limites clínicos.

As regras declaradas no ficheiro de bootstrap local protegido por ACL são
provisionadas na base SQLite apenas quando ainda não existe uma regra com o
mesmo identificador para a missão e começam inativas e sem aprovação. A API
permite gerir a configuração em operação, sem reiniciar o serviço. Estas regras
aplicam-se à missão inteira: para as gerir, o token tem de ser de utilizador,
conter `alerts:configure` explicitamente delegada pela autoridade de identidade
e cobrir todos os astronautas provisionados. A permissão não é concedida por
omissão.

`PUT /api/v1/alerts/rules/{rule_id}` exige `expected_version: 0` ao criar uma
regra e a versão atual ao atualizá-la; a versão seguinte é atribuída pelo
servidor, e fica inativa e não aprovada. Uma versão desatualizada recebe `409
Conflict`; qualquer alteração exige nova aprovação para a versão resultante.
Para desativar, envie `{"expected_version": <versão atual>}` a
`POST /api/v1/alerts/rules/{rule_id}/deactivate`. Reativar uma regra desativada
exige aprovação operacional da versão criada pela desativação.

O fluxo de aprovação é separado da configuração. Um utilizador com a permissão
`alerts:approve`, também explicitamente delegada e com escopo sobre toda a
missão, envia a `POST /api/v1/alerts/rules/{rule_id}/approve` as referências do
protocolo e da fonte, a versão da aprovação e os âmbitos `clinical` e/ou
`operational`. A API regista o principal autenticado como autoridade e a data
do servidor; esses campos não são aceites como declarações do cliente. Cada
aprovação fica vinculada à versão exata da regra. Somente uma aprovação que
inclua `operational` permite ativar essa versão com
`POST /api/v1/alerts/rules/{rule_id}/activate`; uma aprovação apenas clínica não
habilita o motor de alertas. A listagem apresenta o estado (`unapproved` ou
`approved`) e os metadados; a auditoria inclui os eventos de aprovação e
ativação.

Esta infraestrutura regista a decisão e as referências fornecidas, mas não
verifica a autenticidade ou o conteúdo dos documentos citados nem substitui
revisão pela autoridade competente. Nenhuma aprovação ou fonte real é
preconfigurada pelo projeto. Os limiares clínicos mostrados como ilustrativos
continuam explicitamente ilustrativos e não devem ser usados como critérios
clínicos ou operacionais sem aprovação competente. Na inicialização, regras
ativas sem aprovação operacional válida para a versão atual são desativadas e
auditadas; isso inclui regras legadas. A proteção local do bootstrap não é uma
assinatura criptográfica da autoridade terrestre.

`GET /api/v1/alerts/rules/audit` regista ator, instante, ação e snapshots
anteriores/atuais, incluindo provisionamento, aprovação e ativação. Os registos
de auditoria são append-only pela API, mas não são invioláveis nem assinados: um
operador com acesso direto à SQLite pode alterá-los. A missão pode ter até 100
regras ativas; os endpoints de listagem e auditoria são paginados.

Alertas para medições recém-aceites são gravados na mesma transação da medição,
incluindo durante a sincronização offline; reenvios idempotentes não geram um
segundo evento. O endpoint requer `readings:read` e escopo para o astronauta,
com `start`/`end` timezone-aware e paginação. Os eventos são registos de apoio
à monitorização, não diagnósticos, recomendações terapêuticas ou decisões de
aptidão. Não há confirmação/acknowledgment, escalonamento, entrega em tempo
real ou política de retenção configurada. Alterar uma regra não reprocessa
medições antigas nem altera alertas já gerados; a nova versão só é aplicada a
medições aceites após a mudança.

A confirmação de receção requer permissão separada `alerts:acknowledge`,
explicitamente provisionada/delegada, e uma identidade de utilizador com escopo
para o astronauta do alerta. A confirmação é idempotente por utilizador e alerta;
o histórico mostra a contagem e se o utilizador atual confirmou. Significa apenas
que o utilizador registou a receção do evento: não significa resolução, análise
clínica, tratamento ou aptidão, e não existe escalonamento automático.

A análise devolve quantidade, mínimo, máximo, média, mediana, desvio-padrão
amostral, última medição e inclinação linear por dia. `start` e `end` são
obrigatórios e devem incluir fuso horário. Para glicemia, `glucose_context`
também é obrigatório para evitar misturar contextos de medição. A inclinação e
as estatísticas são descritivas; não identificam anomalias nem substituem
avaliação clínica. O endpoint não descarta valores silenciosamente; corrupção
ou valores não finitos persistidos impedem a análise.

O endpoint de cobertura mostra contagens observadas e a hora da última amostra,
incluindo indicadores sem registos. Um zero não significa que uma medição era
esperada ou está em falta: a cadência de recolha ainda não está definida.

O resumo operacional filtra pela hora de recepção e apresenta as contagens
válidas por indicador e origem. `declared_origin` aceita `manual`, `simulated`
ou `nasa`; é uma declaração fornecida pelo emissor, não prova de proveniência.
O conector OSDR cataloga metadados e importa explicitamente ficheiros CSV
públicos autorizados; o endpoint público do painel resume somente quatro
colunas do CMP OSD-575 em memória e não persiste os dados. Nenhum destes dados
é inserido em `health_readings` ou usado por alertas. As rejeições e conflitos
guardam apenas astronauta (quando
identificável), origem declarada, resultado e instante; o payload biométrico
inválido não é copiado para o registo de auditoria. Dados preexistentes sem
`received_at` mantêm esse instante desconhecido e são contabilizados
separadamente, sem inferi-lo a partir do instante de medição.

## Catálogo científico NASA OSDR

O catálogo existente consulta metadados OSDR para um accession `OSD-<número>` e
serve a cópia local sem depender da rede. A descoberta por organismo ou fase de
voo e o inventário de ficheiros também são atualizados explicitamente e ficam
disponíveis em cache offline. A listagem de ficheiros não significa que o
ficheiro foi baixado nem que a sua licença foi verificada.

Importação atual: apenas ficheiros CSV cuja metadata individual da NASA os
marque como não restritos. É exigida a permissão delegada
`scientific-data:import` e a variável positiva `NASA_OSDR_IMPORT_MAX_BYTES`;
não existe um limite de tamanho implícito. O conteúdo original é guardado sem
alteração como BLOB SQLite, com SHA-256, accession, ficheiro, URLs de origem,
metadata remota, data de atualização indicada pela NASA, data da importação,
citação e versão do parser. As linhas analisadas mantêm nomes de coluna e
valores de texto exatamente; a unidade não é convertida (`normalization_status:
not_performed`) e citação/licença continuam `not_verified`.

Os registos científicos importados são consultados pelos endpoints próprios e
nunca são inseridos em `health_readings`, associados automaticamente a um
astronauta ou usados por alertas. O endpoint público do painel obtém o ficheiro
OSD-575 em cada atualização, devolve apenas médias e intervalos observados por
ponto temporal e não persiste o CSV nem as linhas de origem. A transferência
pública do ficheiro não prova direitos de
redistribuição; obter e rever a citação versionada e os termos do ficheiro
antes de publicar ou redistribuir. OSD-575 contém amostras séricas e painéis
metabólicos/imunes/cardiovasculares, não uma série de frequência cardíaca ou
pressão arterial.

O resumo público usa o ficheiro `LSDS-8_Comprehensive_Metabolic_Panel_CMP_TRANSFORMED.csv`
e as colunas de origem de glicose (`mg/dL`), albumina (`g/dL`), creatinina
(`mg/dL`) e ALT (`U/L`). Agrupa por sufixo do nome de amostra, ignora somente
valores vazios, `NA` e `N/A`, e reporta a contagem de valores disponíveis e em
falta. Os identificadores de amostra não são devolvidos. A licença específica
permanece `not_verified`; esta vista é descritiva, histórica e não clínica.

Endpoints (todos requerem identidade de utilizador e permissões explicitamente
delegadas):

- `GET /api/v1/scientific-data/osdr/search` e
  `POST /api/v1/scientific-data/osdr/search/refresh` — consulta ao cache local
  ou descoberta oficial por organismo/fase.
- `GET /api/v1/scientific-data/osdr/studies/{accession}/files` e
  `POST .../files/refresh` — inventário local/atualização no OSDR.
- `POST /api/v1/scientific-data/osdr/studies/{accession}/files/{file_name}/imports`
  — importação explícita, sujeita à permissão e configuração de tamanho.
- `GET /api/v1/scientific-data/osdr/imports[?accession=OSD-575]` e
  `GET /api/v1/scientific-data/osdr/imports/{import_id}/records` — histórico e
  consulta paginada local.

`scientific-data:read` permite consulta, `scientific-data:sync` descoberta e
refresh, e `scientific-data:import` a transferência de ficheiros. Nenhuma
permissão científica é concedida por omissão.

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
O login offline usa desafio de uso único e prova de posse de chave RS256. O
bootstrap pode incluir `authentication_keys` públicos, cada um com `identity_id`,
`key_id` e `public_key_pem`; a identidade correspondente deve declarar o mesmo
`key_id` e o thumbprint `sha256:<SHA-256 do SubjectPublicKeyInfo DER>`. A chave
privada do utilizador/dispositivo permanece no seu autenticador seguro e nunca
é enviada à API. Sem chave pública provisionada, o endpoint não emite desafio
para essa identidade.

Para ativar a emissão, configure `ONBOARD_TOKEN_SIGNING_KEY_PATH` para um
ficheiro PEM PKCS#8 RSA que corresponda à chave pública do serviço onboard e
`AUTH_CHALLENGE_TTL_SECONDS` com uma validade explícita entre 1 e 3600 segundos.
Configure também `AUTH_CHALLENGE_RATE_LIMIT_MAX_REQUESTS` e
`AUTH_CHALLENGE_RATE_LIMIT_WINDOW_SECONDS` com inteiros positivos definidos
pela operação da missão. São obrigatórios quando a emissão de credenciais está
ativa; a aplicação não escolhe uma política por omissão e rejeita a configuração
incompleta no arranque. O limite é uma janela móvel por identidade de utilizador
ou dispositivo, partilhada através da SQLite; a proteção contra abuso por IP e
tráfego distribuído continua a exigir gateway adequado.
O ficheiro da chave tem de ser absoluto, regular, sem reparse point/link,
pertencer à conta do serviço e restringir ACL/permissões conforme o bootstrap;
não é guardado no JSON de bootstrap nem na SQLite. Se a chave emissora não
estiver configurada, os endpoints de autenticação devolvem 503. Se estiver
configurada mas for inválida ou não corresponder ao thumbprint, a aplicação
não inicia.

O fluxo é: solicitar challenge com `subject` e `actor_type`; assinar com a
chave privada do sujeito um JWT `RS256` com cabeçalho `typ: onboard-auth+jwt`,
`kid` provisionado e claims exatas `iss` (subject), `aud` (issuer devolvido),
`iat`, `exp`, `jti` (challenge UUID), `nonce`, `mission_id` e `actor_type`;
enviar a prova, permissões, escopos e duração pretendidos a `/auth/token`.
O servidor verifica identidade, assinatura, uso único, nonce, validade e
delegação e emite tokens. Desafios são substituídos por novos desafios do mesmo
sujeito/ator; uma tentativa inválida não os consome, e uma prova aceite e
emissão de credenciais são gravadas numa transação. As permissões e escopos
solicitados têm de estar provisionados e delegados. O refresh token é opaco,
rotativo e revoga a família se reutilizado; `/auth/revoke` revoga a família
detentora do refresh token.

O endpoint de challenge limita pedidos por identidade numa janela móvel
configurada e persistida em SQLite; isso não substitui proteção por IP,
limitação distribuída entre bases independentes ou mitigação no gateway. A
rotação da chave de autenticação do sujeito requer atualizar o bootstrap por
canal confiável e reiniciar o serviço. A base SQLite não protege contra
rollback/adulteração por administrador local. Não usar dados reais nem expor a
rede antes de validar o provisionamento, gestão de chaves, política temporal,
TLS/mTLS, proteção no gateway e controlos operacionais na missão.

## Sincronização offline (interface do backend)

O separador “Registo offline” guarda medições numa fila IndexedDB no navegador e
envia-as manualmente pelo endpoint v1 quando há ligação. A fila persiste entre
visitas no mesmo perfil do navegador, mas não é cifrada pela aplicação; use
somente um dispositivo gerido e aprovado e não introduza dados reais neste
protótipo. Não há sincronização automática nem reconciliação com o sistema
terrestre na interface. O service worker mantém apenas o shell HTML; pedidos
`/api/*` e respetivas respostas nunca são guardados em cache. O token de
dispositivo é pedido no momento do envio e não é persistido.

Cada medição enviada precisa de um `reading_id` UUID criado
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
Na interface protótipo, o `batch_id` não é persistido: após resposta ambígua, a
fila é reenviada com novos IDs de lote, preservando `reading_id` e sequência.
O serviço identifica as medições já persistidas como `already_received`.

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

### Outbox terrestre (fase inicial)

A v1 permanece local-only. A v2 exige `earth_sync_eligible` como booleano
explícito em cada medição; o campo ausente é inválido. Para qualquer item
elegível, `EARTH_SERVICE_ID` tem de identificar o serviço terrestre de destino.
O emissor é a identidade do serviço onboard derivada do bootstrap validado,
nunca um valor escolhido pelo cliente.

Novas medições elegíveis, o recibo inbound e o snapshot imutável do lote de
saída são gravados na mesma transação SQLite. Linhas antigas migram com
`earth_sync_eligible=0` e não são colocadas automaticamente na outbox. Uma
medição já existente não é alterada nem reenfileirada por um novo pedido. O
SHA-256 guardado verifica a consistência do snapshot; não autentica serviço,
canal ou recibo.

A resposta v2 separa `onboard_status: persisted` de
`earth_delivery_status: pending` e devolve o mesmo `delivery_batch_id` em
replay idempotente. `pending` significa apenas que a obrigação está durável na
outbox local — **não** que foi enviada ou persistida na Terra. O estado e os
dados pendentes não são apagados. O worker one-shot, o transporte HTTPS/mTLS,
o receptor terrestre e os recibos JWT assinados estão implementados. Um lote
só avança para `acknowledged_durable` após validar um recibo Terra assinado que
corresponda ao lote, ao hash canónico e a todos os `reading_id` persistidos.

### Contrato e execução bordo–Terra

O receptor é `POST /api/v1/sync/earth/batches`. O corpo é um envelope JSON
canónico versão 1 com `delivery_batch_id`, `origin_batch_id`,
`source_service_id`, `destination_service_id`, `created_at` e `items`. Cada
item mantém `reading_id`, astronauta, indicador, valor/unidade, instante da
medição e de receção, origem declarada, dispositivo e sequência. O token bearer
JWT RS256 autentica a identidade do serviço onboard e vincula o lote e o
SHA-256 do corpo; o hash não substitui autenticação. O transporte exige HTTPS
com certificado de cliente mTLS. Os certificados TLS e as chaves JWT têm de
ser distintos.

O receptor grava envelope, medições, ligações e recibo na mesma transação
SQLite, devolvendo apenas então um recibo JWT RS256 Terra. `200` indica
`persisted` ou `already_persisted` e confirma exatamente todos os IDs do lote;
`422` indica rejeição permanente; `409` indica conflito isolado. Falha de
transporte, erro 5xx, resposta ausente ou recibo inválido não confirma entrega:
o lote fica em `retry_wait`. Reenvios idênticos recuperam o recibo persistido.
Reutilização de lote, ID de medição com conteúdo diferente ou sequência
dispositivo duplicada nunca sobrescreve os dados. Rejeições e conflitos são
mantidos para análise; não há eliminação automática.

Configure explicitamente no serviço onboard:

- `EARTH_SYNC_ROLE=onboard`,
  `EARTH_SYNC_LOCAL_SERVICE_ID` e `EARTH_SYNC_PEER_SERVICE_ID`;
- `EARTH_SYNC_SIGNING_KEY_PATH` (chave privada JWT) e
  `EARTH_SYNC_PEER_PUBLIC_KEY_PATH` (chave pública de assinatura Terra);
- `EARTH_SYNC_RECEIVER_URL` (URL HTTPS exata do endpoint);
- `EARTH_SYNC_CA_BUNDLE_PATH`, `EARTH_SYNC_CLIENT_CERT_PATH` e
  `EARTH_SYNC_CLIENT_KEY_PATH`;
- `EARTH_SYNC_REQUEST_TIMEOUT_SECONDS`, `EARTH_SYNC_RETRY_BASE_SECONDS`,
  `EARTH_SYNC_RETRY_MAX_SECONDS` e `EARTH_SYNC_LEASE_SECONDS`. São inteiros
  positivos configurados pela operação; o lease tem de exceder o timeout e o
  máximo de retry não pode ser inferior à base.

Execute uma passagem do worker quando o agendador operacional aprovado o
invocar:

```powershell
$env:PYTHONPATH = "backend"
python -m app.earth_sync_worker
```

O comando não configura nem presume uma cadência ou um agendador.

No receptor, configure `EARTH_SYNC_ROLE=earth`, identidades dos serviços,
chave privada de assinatura Terra, chave pública onboard, `EARTH_SYNC_BIND_HOST`,
`EARTH_SYNC_BIND_PORT`, `EARTH_SYNC_SERVER_CERT_PATH`,
`EARTH_SYNC_SERVER_KEY_PATH` e `EARTH_SYNC_CLIENT_CA_BUNDLE_PATH`. Inicie-o
somente pelo runner, que exige certificado de cliente:

```powershell
$env:PYTHONPATH = "backend"
python -m app.earth_receiver
```

O runner ativa a proteção mTLS exigida pelo arranque da aplicação; o endpoint
também rejeita HTTP. Se TLS for terminado num proxy, esse proxy deve exigir e
validar o certificado de cliente e impedir acesso direto ao serviço. Não
publique o endpoint por um servidor FastAPI/Uvicorn genérico. Certificados,
chaves, ACLs, confiança das CAs e identidade do cliente devem ser provisionados
por canal aprovado.

O protótipo inclui fila local do cliente/PWA, mas não implementa cifragem local,
provisionamento ou rotação administrativa de identidades e certificados,
política de retenção nem reconciliação entre múltiplas fontes. Os UUIDs de
dispositivo e identificadores enviados pelo cliente são metadados; a identidade
do dispositivo é verificada pelo token assinado.
A autorização valida as claims assinadas contra a missão, a identidade e a
delegação ativas, além do registo persistido de revogação por `jti`. A migração
SQLite adiciona colunas e tabelas de sincronização/outbox sem apagar registos
existentes. As gravações locais usam transações SQLite,
chaves estrangeiras e `synchronous=FULL`; a durabilidade ainda depende do
armazenamento e da plataforma reais e precisa de validação de falhas. O modo
offline e a sincronização terrestre não foram validados para operação espacial:
requerem testes de falhas físicas, perda de ligação/reinício e revisão de
segurança e missão antes de dados reais.

## Modelos de identidade da missão

Os modelos iniciais de missão, identidade e delegação estão em
`backend/app/mission_identity.py`. Validam relações, missão, referências de
chaves, escopos/permissões máximos e consistência temporal. Os tempos da
delegação e a duração máxima dos tokens são obrigatórios, sem defaults, porque
a política operacional tem de ser definida por missão. O provisionamento e a
validação de delegações estão implementados em módulos separados; não existe,
porém, uma ferramenta administrativa completa para atualizar/revogar
delegações em operação.

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
autorização da API por meio do bootstrap descrito acima. A emissão local de
credenciais está implementada no serviço onboard e nos endpoints de autenticação
offline descritos nesta secção. A rotação de chaves, revogação entre componentes
e políticas temporais operacionais continuam por definir e validar. Isto não
constitui prontidão para uso com dados reais ou em missão.

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
