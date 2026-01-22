# Checkmarx SCA All ☆彡
Checkmarx One: Relatório de Todas Vulnerabilidades SCA

## Descrição

Este script coleta **todas as vulnerabilidades SCA** do **Checkmarx One**, incluindo *confirmadas*, *pendentes* e *em validação*.  
Ele extrai informações detalhadas sobre cada vulnerabilidade, incluindo:
- Nome e ID do projeto  
- ID do scan e do resultado  
- CVE ou pacote afetado  
- Severidade e estado  
- Se está confirmada  
- Autor que comentou ou confirmou  
- Comentário associado  

O objetivo é oferecer uma visão completa das vulnerabilidades SCA e suas interações no ambiente Checkmarx One. Ele consegue puxar até 365 dias (não testei mais que isso)!

---

## Requisitos

### Python
- **Python 3.9+** (recomendado 3.10 ou superior)

### Dependências
Instale via `pip`:
```bash
pip install requests pandas openpyxl
```

---

## Configuração

No início do arquivo `sca_all_comments.py`, configure as variáveis:

```python
AST_API_BASE          = "https://us.ast.checkmarx.net"     # URL base do Checkmarx One AST
SCA_API_BASE          = "https://us.api-sca.checkmarx.net" # URL base do Checkmarx SCA API
CLIENT_ID             = "..."                              # Client ID da aplicação (OAuth)
CLIENT_SECRET         = "..."                              # Client Secret da aplicação (OAuth)
TENANT_NAME           = "..."                              # Tenant do cliente
DEFAULT_LOOKBACK_DAYS = 30                                 # Quantos dias retroceder nas análises
```

> **Importante:**  
> Ajuste as URLs conforme sua região (`US`, `US2`, `EU`, `EU2`) e insira credenciais válidas obtidas no portal Checkmarx One.

Exemplo:
```python
AST_API_BASE          = "https://eu.ast.checkmarx.net"
SCA_API_BASE          = "https://eu.api-sca.checkmarx.net"
CLIENT_ID             = "abcd1234"
CLIENT_SECRET         = "xyz7890"
TENANT_NAME           = "mytenant"
DEFAULT_LOOKBACK_DAYS = 365
```

---

## Funcionamento

O script:
1. Autentica no **IAM** do Checkmarx via OAuth2 (Client Credentials).  
2. Lista todos os projetos do tenant.  
3. Divide o período de busca em **janelas menores** (`--window-days`) para reduzir sobrecarga.  
4. Busca *todos* os scans SCA dentro do intervalo definido (`--days`).  
5. Extrai todos os resultados de vulnerabilidades (não apenas confirmadas).  
6. Usa **GraphQL** para obter autores e comentários de ações.  
7. Exporta um relatório consolidado em **Excel (.xlsx)** e **CSV (.csv)**.

---

## Parâmetros CLI

Você pode executar o script diretamente via terminal com diversos parâmetros:

```bash
python sca_all_comments.py [opções]
```

### Opções disponíveis:

| Parâmetro | Descrição | Padrão |
|------------|------------|--------|
| `--days` | Janela de busca em dias | `30` |
| `--window-days` | Tamanho de cada janela interna | `7` |
| `--output` | Nome do arquivo de saída (.xlsx) | `checkmarx_sca_all.xlsx` |
| `--projects` | Lista separada por vírgulas de projetos (nomes ou IDs) | Todos |
| `--max-rps-gql` | Limite de chamadas GraphQL por segundo | `2.0` |

---

## Saída

O relatório é salvo no diretório atual como:

```
checkmarx_sca_all.xlsx
checkmarx_sca_all.csv
```

### Colunas geradas:

| Campo | Descrição |
|--------|------------|
| Project Name | Nome do projeto no Checkmarx |
| Project Id | ID único do projeto |
| Scan Id | ID do scan analisado |
| Result Id | ID da vulnerabilidade |
| CVE/Package | Nome do pacote ou CVE |
| Severity | Severidade (High, Medium, Low, etc.) |
| State | Estado atual (Confirmed, To Verify, etc.) |
| Confirmed | Indica se foi confirmada (`True` / `False`) |
| Author | Usuário que comentou ou confirmou |
| Author Source | Origem do dado (GraphQL ou CSV Merge) |
| Confirm Note | Comentário do autor |
| Detected First / Last | Datas de detecção inicial e final |

---

## Merge Offline (Histórico CSV)

É possível complementar o relatório com dados antigos usando um CSV histórico:

```python
HISTORY_CSV = r"C:\temp\risk_history.csv"
```

Se configurado, o script tenta casar vulnerabilidades com base em:
- CVE / Package
- ResultId
- SimilarityId
- AlternateId  

Isso permite preencher autores e comentários que não estão mais disponíveis via API.

---

## Exemplo de Execução

Buscar vulnerabilidades dos últimos **60 dias**, com janelas de **10 dias**, para projetos específicos:

```bash
python sca_all_comments.py --days 60 --window-days 10 --projects "api-service,web-app"
```

Saída esperada:
```
[PROJ] api-service (abcd1234)
  janela desde 2025-09-10T00:00:00Z: 4 scans novos
    Scan 98765: 12 SCA
[GQL VARS] scan=98765 proj=abcd mgr=Npm pkg=axios ver=0.21.4 cve=CVE-2023-XXXX
```

---

## Recursos Avançados

- **Rate limit configurável** (`--max-rps-gql`) para evitar bloqueios.  
- **Cache inteligente** de chamadas GraphQL.  
- **Tratamento robusto de erros e timeouts**.  
- **Paginação automática** em grandes tenants.  
- **Merge CSV opcional** para histórico offline.  
- **Exportação dupla (Excel + CSV)** para compatibilidade com Power BI, Excel ou scripts de auditoria.

---

## Estrutura do Código

```
sca_all_comments.py
├── Configuração inicial (URLs, tokens, parâmetros)
├── Funções auxiliares (_is_sca, parse_pkg, etc.)
├── GraphQL Query + Rate Limit
├── Classe HistoryIndex (merge CSV)
├── Paginação de projetos/scans/resultados
├── collect_sca_findings()  # Coleta principal
├── export_report()         # Geração do Excel/CSV
└── CLI (argparse)          # Execução com parâmetros
```

---
☆彡
