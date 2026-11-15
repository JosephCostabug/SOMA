# NASA OSDR e Inspiration4: levantamento inicial

**Estado:** levantamento documental e conector limitado a metadados públicos;
nenhum arquivo científico ou dado biomédico foi copiado para o repositório.
**Consultado em:** 2026-11-14.
**Objetivo:** identificar dados e referências reutilizáveis para pesquisa e
contexto, sem os tratar como limites clínicos nem como telemetria operacional.

## Conclusões

1. O OSD-575 é confirmado no API oficial do NASA Open Science Data Repository
   (OSDR) como **SpaceX Inspiration4 Blood Serum Metabolic Panel and
   Immune/Cardiac Cytokine Arrays**. O registo informa soro humano, missão
   Inspiration4 de 16 a 18 de setembro de 2021 e identificadores `LSDS-8` e
   `GLDS-579`.
2. OSD-575 contém painéis séricos analisados antes/depois da missão: painel
   metabólico abrangente, painéis multiplex imune e cardiovascular. O HDCVD9 é
   um painel de biomarcadores/proteínas cardiovasculares. Isto **não** é uma
   série de frequência cardíaca, pressão arterial ou sinais vitais contínuos.
3. O artigo principal da missão também relata fisiologia cardiovascular,
   medidas com smartwatch/wearables, cognição, sono e estados comportamentais.
   Descreve a Alertness and Mood Survey (AMS), duração do sono e avaliações
   repetidas durante as fases da missão. Esses resultados não significam que
   esses dados sejam todos disponibilizados no OSD-575 nem que possam ser
   convertidos diretamente nos indicadores de monitorização deste projeto.
4. O artigo SOMA informa depósitos associados à missão em quatro
   repositórios/catálogos: NASA GeneLab, NASA ALSDA, SOMA Data Portal e TRISH
   EXPAND. Para sono, comportamento e séries cardiovasculares, a próxima
   pesquisa deve localizar e avaliar os registos/arquivos específicos nesses
   catálogos, sem assumir que OSD-575 os contenha.
5. Não foi encontrada uma licença explícita do ficheiro/dataset OSD-575 nos
   campos de metadados consultados. A política segura é citar a versão exata no
   botão de citação da página do estudo e verificar as condições de cada ficheiro
   antes de redistribuir, incorporar num produto ou derivar uma base de dados.
   A licença CC BY 4.0 confirmada para um artigo científico não deve ser
   presumida para todos os dados associados.

## Inventário verificado: OSD-575

| Campo | Resultado |
|---|---|
| Acesso OSDR | [`OSD-575`](https://osdr.nasa.gov/bio/repo/data/studies/OSD-575) |
| Registo de metadados consultado | [NASA OSDR Biological Data API — OSD-575](https://visualization.osdr.nasa.gov/biodata/api/v2/dataset/OSD-575/) |
| Título no catálogo | SpaceX Inspiration4 Blood Serum Metabolic Panel and Immune/Cardiac Cytokine Arrays (Comprehensive Metabolic Panel and Multiplex) |
| Identificadores | OSD-575; LSDS-8; GLDS-579 |
| Missão/material | SpaceX Inspiration4; `Homo sapiens`; soro |
| Datas da missão no catálogo | 2021-09-16 a 2021-09-18 |
| Tipo de dados | Dados de ensaio laboratorial sérico; valores metabólicos e painéis multiplex imune/cardiovascular |
| Medidas de telemetria de pulso/pressão | Não indicadas como conteúdo deste estudo |
| Licença específica do dataset | Não identificada nos campos consultados; verificar a página e a citação/versionamento de cada ficheiro antes de reutilização/redistribuição |

O API lista versões submetidas e transformadas, incluindo:

- `LSDS-8_Multiplex_serum_cardiovascular_EvePanel_TRANSFORMED.csv`
- `LSDS-8_Multiplex_serum_immune_EvePanel_TRANSFORMED.csv`
- `LSDS-8_Multiplex_serum.immune.AlamarPanel_TRANSFORMED.csv`
- `LSDS-8_Comprehensive_Metabolic_Panel_CMP_TRANSFORMED.csv`

O catálogo descreve o HDCVD9 (Eve Technologies) como painel cardiovascular
Discovery 9-Plex; o HD71 como painel de citocinas/quimiocinas 71-Plex; o Alamar
NULISA-seq como painel de inflamação; e o CMP como painel metabólico. O catálogo
relata que certas medidas foram normalizadas pela média pré-voo da tripulação e
que dados Alamar incluem normalizações e unidades NPQ. Portanto, **não** se deve
misturar valores normalizados, concentrações e indicadores clínicos em tempo
real sem ler o protocolo, o dicionário de colunas e a unidade original de cada
ensaio.

## Inspiration4: evidência científica relevante

O estudo principal avaliou quatro tripulantes civis numa missão orbital de três
dias. O artigo descreve wearables/smartwatches, fisiologia, cognição,
neurovestibular e estados comportamentais. A AMS recolheu sono e estado
comportamental nas fases da missão; o artigo relata duração de sono média em
voo e resultados subjetivos de alerta/humor. Estes achados são uma referência
para desenhar variáveis e protocolos, não uma população de referência clínica:
amostra pequena, missão curta e medições dependentes do protocolo.

O estudo complementar de perfis imunes/multi-ômicos analisa respostas celulares
e imunes. É contexto de investigação de mecanismos, não uma fonte direta para
calibrar limites de frequência cardíaca, glicemia ou outros sinais vitais.

### Candidatos para a etapa seguinte

| Necessidade | Fonte/caminho de descoberta | Critério de seleção |
|---|---|---|
| Sono e ritmos | Artigo Inspiration4 e arquivos associados em OSDR/SOMA/TRISH; NASA Life Sciences Portal / Standard Measures | Confirmar dados por participante/fase, método (diário, AMS, actigrafia), unidades, datas e licença |
| Humor, alerta e comportamento | AMS descrita no artigo; procurar dados/arquivos de avaliação comportamental vinculados à missão | Preservar escala, versão do instrumento, direção da escala, fase e contexto; não converter em diagnóstico |
| Fisiologia cardiovascular | Wearables e medidas fisiológicas descritos no artigo; OSD-575 para biomarcadores séricos cardiovasculares; NASA Life Sciences Portal | Separar séries vitais (HR/pressão) de biomarcadores séricos; identificar sensor, taxa de amostragem, unidades, sincronização e qualidade |
| Contexto de missões e medidas padronizadas | [NASA Life Sciences Portal](https://nlsp.nasa.gov/explore) e [Standard Measures](https://nlsp.nasa.gov/resources/standard-measures) | Preferir medidas humanas de voo/análogos com protocolo público e metadados comparáveis |

Uma seleção de datasets adicionais só deve ser feita depois de confirmar,
individualmente, que o OSDR/NLSP contém os arquivos pretendidos, as variáveis,
os metadados de qualidade e as condições de acesso/licença. A API de dados
biológicos do OSDR anuncia pesquisa de metadados e consulta de datasets, ensaios
e amostras; os seus filtros e formatos devem ser usados para catalogação
reprodutível.

## Implementação do catálogo no backend

O backend consulta a API de metadados do OSDR para um accession
`OSD-<número>` pedido explicitamente, permite descobrir datasets por organismo
ou fase de voo e mantém um inventário de ficheiros em cache local. Metadados e
inventário podem ser lidos offline depois de consultados. A fonte consultada é
[NASA OSDR Biological Data API](https://visualization.osdr.nasa.gov/biodata/api/v2/dataset/OSD-575/).

Existe também importação explícita de ficheiros CSV marcados individualmente
pela NASA como não restritos. A permissão `scientific-data:import` e o limite
operacional `NASA_OSDR_IMPORT_MAX_BYTES` são obrigatórios. A importação guarda
os bytes originais, linhas analisadas sem conversão de valores e o registo de
proveniência; `files_downloaded` só é verdadeiro quando existe uma importação
persistida para o estudo. A leitura da importação permanece disponível offline.
Falhas de rede ou validação não substituem importações anteriores. A citação e
a presença do registo no catálogo não atestam licença ou autorização para
reutilizar/redistribuir os dados associados. A normalização de unidades e
formatos além de CSV ainda não está implementada; confirmar também versão,
atribuição exigida e semântica de cada variável antes de utilização científica.

### Gate para formatos e mapeamentos científicos

Uma verificação dos metadados oficiais de ficheiros confirma que a extensão
indica diferentes tipos de conteúdo, não uma semântica uniforme:

| Ficheiro oficial | Metadata OSDR | Decisão para esta integração |
|---|---|---|
| OSD-569 `LSDS-7_Complete_Blood_Count_CBC_TRANSFORMED.csv` | Categoria `Complete Blood Count`, 9.317 bytes, `restricted: false` | CSV pode ser arquivado e consultado como valores de origem; não é uma das métricas operacionais atuais e não deve ser convertido em sinal vital. |
| OSD-575 `LSDS-8_Multiplex_serum.immune.AlamarPanel_SUBMITTED.xlsx` | Categoria `Immunoassay`, 322.799 bytes, `restricted: false` | XLSX não é aceite pelo importador CSV. O nome/categoria não define um esquema clínico nem uma unidade normalizada. |
| OSD-569 `GLDS-561_long-readRNAseq_Direct_RNA_seq_Gene_Expression_Processed.xlsx` | Categoria `long read RNA-Seq`, 123.312.037 bytes, `restricted: false` | XLSX de expressão génica não é um dataset de sinais vitais e fica fora da ingestão tabular atual. |

Os tamanhos e categorias acima vêm da API oficial de metadata por ficheiro,
consultada em 2026-11-15; os conteúdos não foram descarregados nem importados.
O `restricted: false` indica o estado apresentado pelo catálogo, não uma licença
de redistribuição. O endpoint deve continuar a rejeitar XLSX com `415` até
existir um parser de workbook que preserve folhas, cabeçalhos, tipos/valores de
origem e localização das linhas, e que tenha contrato e testes próprios.

Antes de qualquer mapeamento para indicadores operacionais, exigir por ficheiro:
documentação de variáveis e unidades, identificação de colunas/códigos,
tratamento de valores ausentes/qualificadores, validação contra o conteúdo e
versão exatos, citação e termos de uso. Sem esta evidência, guardar os valores
como dados científicos de origem ou não importar; não inferir equivalência
clínica pela semelhança do nome de uma coluna.

## Seguimento: dados de sono, comportamento e wearable

A revisão do artigo principal e das páginas do projeto confirma que estas
medidas foram recolhidas ([Jones et al., 2024](https://pmc.ncbi.nlm.nih.gov/articles/PMC11357997/)),
mas **não** identifica um accession público nem fornece os arquivos brutos
desses sinais:

| Domínio | O que a publicação confirma | Limite da evidência/acesso |
|---|---|---|
| Sono e comportamento | A Alertness and Mood Survey (AMS) recolheu duração do sono e estado comportamental. A duração foi derivada de horários de sono e despertar autorrelatados. Dez itens AMS usaram escalas tipo Likert de 11 pontos nas fases pré-voo, voo e pós-voo (N=26 respostas por item). Incluiu qualidade do sono, sonolência, carga de trabalho, exaustão, doença, humor e stress. | Não é evidência de actigrafia nem de medição automática do sono. A figura suplementar descreve os resultados, mas não identifica o accession nem disponibiliza os registos individuais. |
| Cardiovascular | O Apple Watch Series 6 foi usado em períodos selecionados das três fases para frequência cardíaca (HR), variabilidade da frequência cardíaca (HRV), saturação de oxigénio (SpO₂), atividade e consumo de energia. A Extended Data Fig. 12 reporta médias horárias: HR N=424, HRV N=127 e SpO₂ N=177; medições de SpO₂ falharam em voo para dois tripulantes. | Estes números são contagens de observações sumarizadas no artigo, não frequência de amostragem ou cobertura completa. A publicação não fornece aqui o ficheiro bruto, esquema, unidades detalhadas de todos os campos ou accession específico. |
| ECG e outros dados de wearable | A discussão do artigo inclui HR e eletrocardiograma entre os dados de wearables guardados nos repositórios da missão. | A menção não permite concluir que haja um traçado ECG público, nem identificar formato, taxa de amostragem, titularidade ou licença. |

O artigo informa que os conjuntos foram depositados em quatro repositórios:
NASA OSDR (incluindo GeneLab e ALSDA), SOMA Data Portal e TRISH EXPAND
(TrialX) ([Jones et al., 2024](https://pmc.ncbi.nlm.nih.gov/articles/PMC11357997/)).
A discussão caracteriza o acesso aos dados da missão como
controlado e enumera, entre os conteúdos, inquéritos qualitativos recebidos
por aplicações móveis, dados de wearables e dados médicos. A página pública
do [SOMA Browser](https://soma.weill.cornell.edu/apps/SOMA_Browser/) é útil
para explorar as análises omics, mas não é, por si só, prova de que os registos
brutos de AMS ou wearable estejam disponíveis sem autorização.

### Série pública OSDR da missão

A API biológica oficial confirmou sete registos consecutivos com missão
Inspiration4 e inventários de ficheiros, **OSD-569 a OSD-575**. Os títulos,
descrições, materiais e nomes de ficheiros indicam estes conteúdos:

| Accession | Conteúdo indicado pelo registo e inventário OSDR | Relevância para o backend |
|---|---|---|
| [OSD-569](https://osdr.nasa.gov/bio/repo/data/studies/OSD-569) | Sangue total; inclui hemograma completo (CBC), RNA-seq, m6A, WGS e hematopoiese clonal. Há ficheiros CSV do CBC submetidos e transformados. | CBC é medição laboratorial; não é pressão arterial nem sinal vital contínuo. |
| [OSD-570](https://osdr.nasa.gov/bio/repo/data/studies/OSD-570) | PBMC: snRNA-seq, snATAC-seq e perfis de repertório T/B. | Pesquisa molecular/celular; não é telemetria clínica. |
| [OSD-571](https://osdr.nasa.gov/bio/repo/data/studies/OSD-571) | Plasma: proteómica, vesículas extracelulares, metabolómica, cfDNA e cfRNA. | Ensaios de laboratório e multi-omics; não equivale a sinais vitais. |
| [OSD-572](https://osdr.nasa.gov/bio/repo/data/studies/OSD-572) | Zaragatoas orais, nasais e da pele; metagenómica e metatranscriptómica. | Microbioma; fora do escopo atual de sinais vitais/sono. |
| [OSD-573](https://osdr.nasa.gov/bio/repo/data/studies/OSD-573) | Zaragatoas de superfícies da cápsula Dragon; metagenómica e metatranscriptómica. | Microbioma ambiental, não medição do astronauta. |
| [OSD-574](https://osdr.nasa.gov/bio/repo/data/studies/OSD-574) | Biópsias de pele deltoide, transcriptómica espacial e dados de microbioma. | Tecido/omics; não é sinal vital. |
| [OSD-575](https://osdr.nasa.gov/bio/repo/data/studies/OSD-575) | Soro: painel metabólico abrangente e painéis imune/cardiovascular. | Biomarcadores séricos, não HR, pressão arterial ou série contínua. |

As listas de ficheiros foram consultadas pela
[API oficial OSDR](https://visualization.osdr.nasa.gov/biodata/api/), sem
transferir conteúdo biomédico. A pesquisa por nomes de ficheiros não encontrou
sono, AMS, HR, HRV, SpO₂ ou ECG nos sete inventários. Isto não prova que essas
medidas estejam ausentes de todos os repositórios: o artigo também aponta para
SOMA e TRISH EXPAND/TrialX.

**Acesso por ficheiro:** a documentação OSDR diz que a restrição pode variar
dentro de um mesmo estudo. O estado deve ser verificado no separador Files da
página de cada estudo (ícone de cadeado e botão de pedido de acesso); a simples
presença do nome numa resposta da API não demonstra permissão para descarregar,
reutilizar ou redistribuir. Para ficheiros controlados, o processo oficial
solicita formulário, aprovação IRB, verificação de afiliação, avaliação do
comité de acesso e aceitação do Data User Agreement. A autorização limita
finalidade e período, exige salvaguarda/eliminação de cópias e define citações
e créditos. Ver [Request Controlled Access Datasets from OSDR](https://osdr-tutorials.readthedocs.io/en/latest/pages/guides/request_controlled_access_datasets.html).

O [SOMA Browser](https://soma.weill.cornell.edu/apps/SOMA_Browser/) identifica
análises e publicações relacionadas com Inspiration4, incluindo dados
multi-omics. A página informa também que o conteúdo do site é protegido por
direitos autorais salvo indicação em contrário. A disponibilidade de um
visualizador público não confirma licença ou autorização para extrair e
incorporar dados de participantes no backend.

### Decisão para a integração

1. Manter OSD-569 a OSD-575 como fontes de pesquisa distintas e tipadas
   (hemograma, omics, microbioma e ensaios séricos); não os misturar com sinais
   biométricos em tempo real.
2. Não copiar nem integrar dados individuais de AMS ou wearable até obter o
   accession e ficheiro exatos, documentação de campos/unidades, condições de
   acesso, licença e autorização aplicável.
3. Na próxima etapa, solicitar ou localizar nos portais autorizados o
   inventário específico de ficheiros de sono/AMS e wearable, e registar a
   proveniência e versão fornecidas pelo titular.
4. Se a autorização não permitir redistribuição, o backend deve guardar apenas
   metadados bibliográficos ou referenciar a origem autorizada; não armazenar
   cópias dos dados brutos.

## Direitos, uso e crédito

- **Citar o dataset exato:** a FAQ do NASA OSDR recomenda usar o botão de citação
  da página do estudo; a citação inclui a versão e pode ser exportada em BibTeX
  ou RIS. Para OSD-575, obter essa citação antes de publicar ou distribuir
  resultados; este levantamento não inventa um DOI nem uma versão do dataset.
- **Crédito institucional:** a FAQ recomenda reconhecer o NASA OSDR quando os
  dados, assistência ou revisão do OSDR forem usados. A formulação geral
  recomendada é: “Data are courtesy of the NASA Open Science Data Repository
  (https://osdr.nasa.gov/bio/repo)”. Para visualizações, seguir também as
  frases específicas do portal e indicar a versão quando solicitado.
- **Licenças são por recurso:** a publicação em acesso aberto e a disponibilidade
  de download não constituem, por si sós, prova de que todos os dados, tabelas,
  imagens ou materiais de terceiros tenham a mesma licença. O artigo de Jones
  et al. tem licença CC BY 4.0 registada para o DOI do artigo; isso cobre o
  artigo nos termos dessa licença, mas não estende automaticamente a licença
  aos arquivos de OSDR, SOMA ou TRISH.
- **Antes de redistribuir:** guardar a URL do recurso, accession, versão/data de
  consulta, citação oficial, licença/termos aplicáveis e proveniência; conferir
  consentimento, condições de acesso, atribuição requerida e restrições dos
  contribuidores. Não copiar dados pessoais ou dados com acesso controlado para
  o repositório.
- **Uso no sistema:** dados científicos não são valores normativos nem
  recomendações clínicas. Não alimentar alertas de apoio operacional ou decisões
  de saúde com valores de pesquisa sem revisão científica, médica, regulatória
  e de risco apropriada.

### Modelo de crédito para documentação do projeto

> Dados do NASA Open Science Data Repository (OSDR), estudo OSD-575
> (Inspiration4), consultados em 2026-11-14. Citar a versão e a referência
> bibliográfica fornecidas pela página oficial do dataset; seguir a licença e
> os termos de uso aplicáveis ao arquivo utilizado.

Este texto é um registo de proveniência do projeto, não substitui a citação
oficial do estudo nem os termos do titular dos dados.

## Referências

1. **NASA OSDR.** OSD-575, *SpaceX Inspiration4 Blood Serum Metabolic Panel and
   Immune/Cardiac Cytokine Arrays*. [Página do estudo](https://osdr.nasa.gov/bio/repo/data/studies/OSD-575);
   [metadados/API](https://visualization.osdr.nasa.gov/biodata/api/v2/dataset/OSD-575/).
   Arquivos e protocolos consultados via API em 2026-11-14.
2. **Jones CW et al.** “Molecular and physiological changes in the SpaceX
   Inspiration4 civilian crew.” *Nature* 632, 1155–1164 (2024).
   [DOI: 10.1038/s41586-024-07648-x](https://doi.org/10.1038/s41586-024-07648-x);
   [texto completo PMC11357997](https://pmc.ncbi.nlm.nih.gov/articles/PMC11357997/);
   [registo Crossref](https://api.crossref.org/works/10.1038/s41586-024-07648-x).
   O registo Crossref do DOI indica CC BY 4.0 para o artigo; confirmar as
   condições na página do editor antes de reutilizar conteúdo específico.
3. **Kim J et al.** “Single-cell multi-ome and immune profiles of the
   Inspiration4 crew reveal conserved, cell-type, and sex-specific responses to
   spaceflight.” *Nature Communications* 15, 4954 (2024).
   [DOI: 10.1038/s41467-024-49211-2](https://doi.org/10.1038/s41467-024-49211-2);
   [Europe PMC](https://europepmc.org/article/MED/38862516).
4. **Overbey EG et al.** “The Space Omics and Medical Atlas (SOMA) and
   international astronaut biobank.” *Nature* 632, 1145–1154 (2024).
   [DOI: 10.1038/s41586-024-07639-y](https://doi.org/10.1038/s41586-024-07639-y);
   [Europe PMC](https://europepmc.org/article/MED/38862028).
5. **Gebre SG et al.** “NASA Open Science Data Repository: Open Science for
   Life in Space.” *Nucleic Acids Research* 53(D1), D1697–D1710.
   [DOI: 10.1093/nar/gkae1116](https://doi.org/10.1093/nar/gkae1116).
6. **NASA OSDR FAQ.** [Citação, crédito institucional, acesso e orientação sobre
   os portais](https://science.nasa.gov/reference/osdr-faq/).
7. **NASA OSDR Data API.** [Documentação OpenAPI](https://visualization.osdr.nasa.gov/biodata/api/).
8. **NASA Life Sciences Portal.** [Pesquisa de dados humanos](https://nlsp.nasa.gov/explore);
   [NASA Standard Measures](https://nlsp.nasa.gov/resources/standard-measures).
9. **SOMA.** [Página do projeto Inspiration4 e ligações para o SOMA Browser](https://soma.weill.cornell.edu/);
   [SOMA Browser](https://soma.weill.cornell.edu/apps/SOMA_Browser/). A página do
   browser indica que o conteúdo do site é protegido por direitos autorais salvo
   indicação em contrário; isso não define, por si só, a licença de cada dataset.
10. **NASA OSDR Tutorials.** [Acesso a datasets controlados](https://osdr-tutorials.readthedocs.io/en/latest/pages/guides/request_controlled_access_datasets.html)
    e [uso da Biological Data API](https://osdr-tutorials.readthedocs.io/en/latest/pages/guides/biological_data_api.html).
    Consultado em 2026-11-14.
