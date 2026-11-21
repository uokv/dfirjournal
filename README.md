# DfirTrace

Interface para ler o USN Journal do NTFS. O programa abre o volume, lista as entradas e resolve o identificador do arquivo para um caminho legível.

Esta versão parte do JournalTrace e acrescenta um check de integridade do `$UsnJrnl`. A leitura normal mostra o que o sistema ainda devolve. O check compara esse intervalo com o `$J` e o `$Max` em disco e marca sinais de journal oco, cortado, sobreposto ou divergente.

## Check de integridade

Depois que o scan do volume termina, marque **cleaneds** na grade. O processo precisa estar elevado (Administrador): a leitura abre o volume e o fluxo `\\?\X:\$Extend\$UsnJrnl`.

O rótulo passa a `cleaneds (N)`. `N` é a quantidade de sinais. Cada registro conta nos códigos de entrada (`0xU1` a `0xU4`, `0xU6` a `0xU8`, `0xUB`). Ghost, buraco no intervalo ativo, faixa de zeros e divergência do `$Max` contam como um sinal cada.

A coluna **cleaned** grava o achado na linha do mesmo USN. Achado que não existe na grade — leitura crua do `$J`, `$Max`, ghost, buraco, wipe — entra como linha extra. Com o checkbox marcado, a busca fica restrita às linhas que têm sinal. Desmarcar remove essas linhas extras. O resultado fica em cache até o próximo scan.

| Estado | Significado |
| --- | --- |
| Limpo | Nenhum sinal no intervalo lido |
| Detectado | Um ou mais sinais; o total aparece no checkbox |
| Inativo | Journal sem ID, ou `NextUsn` sem intervalo útil |
| Não verificado | Volume não abriu, o journal não respondeu, a leitura quebrou, há menos de 1000 registros, ou o layout dos registros foge do padrão |

Numa leitura fraca (falha, poucos registros ou deslocamento de nome fora do comum), os códigos `0xU1`, `0xU2`, `0xU3`, `0xU4` e `0xU7` ficam de fora. Os sinais que vêm do `$J` e do `$Max` continuam valendo.

### Códigos

| Código | O que observa |
| --- | --- |
| `0xU1` | Sobra dentro do registro, depois do nome alinhado a 8 bytes. Se esses bytes formam um nome legível, ele aparece no achado. |
| `0xU2` | O carimbo de hora recua mais de 60 segundos e o registro seguinte volta à faixa anterior, ou avança mais de 60 segundos e o seguinte cai de volta. |
| `0xU3` | Registro V2 com nome vazio, referência de arquivo zerada, timestamp zerado ou reason zerado. |
| `0xU4` | Salto de USN para a frente maior que 64 KB. Se o journal passa de 1 MB e a soma desses saltos passa de 512 KB e de 10% do intervalo, sai também uma linha de cobertura. |
| `0xU5` | `FSCTL_READ_USN_JOURNAL` devolve só o próximo USN, e `NextUsn - FirstUsn` passa de 10 MB. O check encerra nesse ponto e mantém o que o `$J` e o `$Max` já tiverem mostrado. |
| `0xU6` | No `$J` cru, registro com cabeçalho e USN igual a zero. A coluna USN dessa linha é o deslocamento no arquivo. |
| `0xU7` | O USN volta mais de 64 KB em relação ao fim do registro anterior. |
| `0xU8` | No `$J` cru, o USN do registro não é o deslocamento dele no fluxo. No NTFS esse campo é o offset do registro. |
| `0xU9` | Clusters ainda alocados no `$J` antes de `FirstUsn`. |
| `0xUA` | `$Extend\$UsnJrnl:$Max` discorda do `FSCTL_QUERY_USN_JOURNAL` em tamanho máximo, delta de alocação, ID do journal ou menor USN válido. |
| `0xUB` | Entre dois USNs consecutivos o vão é de pelo menos 800 bytes, acima do tamanho de um `USN_RECORD_V2`. A linha sai como `Hook USN Journal` com o horário do registro anterior. |
| `0xUC` | Faixa contínua de zeros de 32 KB ou mais no `$J` alocado, ou pelo menos quatro faixas de 4 KB. |
| `0xUE` | Bytes sem alocação dentro do intervalo ativo, de `FirstUsn` até `NextUsn`. |

A grade mostra até 500 linhas por categoria. O restante entra como `(+N registros)`. A leitura segue o journal inteiro, e a caminhada do `$J` percorre todo o intervalo ativo. Entram registros V2 e V3.

Esses códigos são indícios no layout do journal. Um salto grande também aparece quando o NTFS descarta a parte antiga do `$J` no uso normal.

## Filtros

1. **Inclusão (`&&`)**: várias condições na mesma coluna.
2. **Exclusão (`!!`)**: tira um valor do filtro.
3. **Alternativa (`||`)**: qualquer um dos valores na coluna.
4. **Várias colunas**: `coluna:valor;coluna:valor`.

A coluna pode ficar de fora quando a busca usa `&&`, `!!` ou `||`. Nesse caso vale a coluna selecionada na interface (o padrão é o nome).

### Exemplos

- **Busca simples**: `.exe` procura `.exe` na coluna ativa.
- **Inclusão**: `name:rundll32&&.pf` exige `rundll32` e `.pf` no nome.
- **Exclusão**: `name:.exe!!svchost` exige `.exe` e dispensa `svchost`.
- **Alternativa**: `name:.exe||.dll` aceita `.exe` ou `.dll`.
- **Duas colunas**: `name:.pf;reason:delete` exige `.pf` no nome e `delete` no motivo.

Os checkboxes de motivo (`File delete`, rename, stream change, basic info change) combinam com o texto da busca.

## Licença

O projeto segue a [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).

## Contribuidores

- [emv](https://github.com/emv901)
- [spokwn](https://github.com/spokwn)
