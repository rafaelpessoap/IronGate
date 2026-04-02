# IronGate 🛡️
**Sistema de Monitoramento e Proteção em Tempo Real**

O **IronGate** é um daemon único desenvolvido nativamente em Rust, feito especialmente para monitorar acessos ao **OpenLiteSpeed (OLS)** em tempo real sem qualquer degradação de tráfego. O aplicativo rastreia comportamentos anômalos de bots maliciosos (Brute Forces, Scans, AJAX/Cart Floods), atribuiu pontuações de ameaça dinâmicas e **bloqueia atacantes instantaneamente** a nível de `.htaccess`.

---

## 🎯 O Que é e o Problema que Resolve

Em ambientes onde regras PHP impõem excesso de overhead em conexões massivas (arquiteturas como `block_bots.php` operando dependentes do disco e interpretadores via **APCu**), ocorre grande vazamento de dados de ameaças durante restarts do servidor ou estouros de capacidade.

**IronGate resolve isso operando Fora do Nível Aplicacional:**
- Ele analisa os logs puros `access.log` do servidor na sua máquina em tempo real usando inotify e Linemux.
- Trabalha em Background (Zero Overhead para o cliente/Visitantes).
- Executa Invariantes bloqueando apenas no `.htaccess` nativo do painel e pedindo graceful restart apenas de forma estrita.
- Possui uma pegada de alocação de memória infíma (`~15MB`) substituindo todas as stacks velhas.

## ⚙️ Arquitetura

1. `log_ingestor`: Monitora através de hooks paralelos assíncronos a criação das sentenças de Log e parseia para metadados legíveis.
2. `analytics`: Engine de análise por IP que agrupa janelas deslizantes (`Sliding windows`) em contadores de tempo. Gera pontuações baseados num leque de "Regras Invariantes" mapeáveis pela aplicação (`ajax_flood`, `checkout_spam`, etc).
3. `enforcer`: Escreve com segurança em modo "Apenas o Meu Bloco" os acessos negados utilizando Atomic Renames, gerando backups dinâmicos a cada requisição ao `.htaccess`. Mantem as definições de outros sistemas intactas.
4. `dashboard`: Webpage visual e em tempo real abastecida em porta VPN restrita usando conexões WebSockets persistentes para controle absoluto (Comandos como: Liberar IPs, Banir ou Ativar Modo Emergência).

## 🚀 Como Iniciar (Deploy)

### Pré-requisitos
- Sistema Linu/macOS.
- Permissoes de leitura nas pastas de log (ex: `/usr/local/lsws/logs/access.log`)
- Binários do OpenLiteSpeed para o restart de enforcer (`/usr/local/lsws/bin/lswsctrl restart`)

### Compilação e Deploy (Linux Ubuntu/Debian x86_64)
Na sua máquina de desenvolvimento com a versão devidamente atualizada do cargo:
```bash
cargo build --release --target x86_64-unknown-linux-gnu
```
Mande o binário para o seu servidor, libere permissão com `chmod 755` e registre a daemon no **systemd** configurando os apontamentos pelo arquivo de base no raiz do programa: `config.toml`. 

Acompanhe as métricas após ativado via terminal nativo no seu server em **`10.8.0.1:9847`**.
