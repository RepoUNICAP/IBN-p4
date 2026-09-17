# ☱IBN scan-block
--------

Projeto feito visando a aplicação real de uma rede baseada em intenção (IBN) implementada em **p4** que pode detectar e bloquear automaticamente **scans** de rede, com um um controlador em python que traduz intenções do operador para configuração do switch em tempo real.

**ALUNOS**:
- Eduardo Costa Braga
- Henrique Franca Alves de Lima
- Isabela Medeiros Belo Lopes
- Julia Vilela Cintra Galvão
- Rafael Viana Angelim
- Reuel
# ☱Premissa
------ 

Por ser uma linguagem em adição ao OpenFlow, que prometia não ceder a obrigatoriedade e à limitação da arquitetura top to bottom. Enquanto isso, como foi pedido para a atividade, a implementação de uma rede baseada em intenção (IBN) se resume em fazer com que dada uma certa instrução do operador da rede, a própria funcione de um determinado modo.
Para isso, visualizamos uma problemática que já havíamos visto na área de segurança, o scanning de rede, principalmente .
- Ferramentas como o nmap, zmap, angry scanner, são mapeadores de rede que buscam portas abertas em um certo dispositivo, procurando comunicação ou, na maioria dos casos, vulnerabilidades existentes. Com isso, ao analisar o comportamento especificamente do nmap, verificamos que ele manda várias requisições TCP, onde para cada uma, para um dos scans mais usados, o half-open scan, manda uma requisição SYN para conexão para cada uma das portas sem retornar o ACK.
- Com isso, chegamos na nossa implementação. Uma rede baseada em intenção que contabiliza requisições SYN para IPs individuais e as armazena em uma tabela hash, caso o número de requisições ultrapasse um valor pré estabelecido, o operador pode escolher, por exemplo, bloquear o IP específico permanentemente ou durante um período de tempo de sua escolha. A nossa IBN tem as seguintes funcionalidades 
	- Ligar/Desligar o bloqueio automático de IPs maliciosos
	- Bloquear/Desbloquear um IP específico (permanentemente ou dado um período especificado)

# ☱Arquitetura
---------

O projeto tem duas partes que se comunicam:
- **[ibn-scanblock.p4](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/ibn-scanblock.p4)** - Programa p4 que roda no switch (BMv2)
- **[ntent.py](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/intent.py)** - Controlador da IBN (interpretador e tradutor)

# ☱Estrutura do repositório
------ 

|Arquivo|Descrição|
|---|---|
|[scan-block/ibn-scanblock.p4](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/scan-block/ibn-scanblock.p4)|Programa P4: parser, contagem de SYNs, ACL manual|
|[scan-block/intent.py](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/scan-block/intent.py)|Controlador IBN: Interpretador de intenção, aplicação no switch, status|
|[scan-block/receive.py](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/scan-block/receive.py)|Roda no host receptor e mostra, em tempo real, os pacotes TCP chegando|
|[scan-block/topology.json](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/scan-block/topology.json)|Topologia Mininet: hosts h1/h2/h3 ligados a um switch s1|
|[scan-block/s1-runtime.json](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/scan-block/s1-runtime.json)|Entradas de tabela (P4Runtime) - forwarding L2/L3 pra h1, h2 e h3|
|[scan-block/Makefile](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/scan-block/Makefile)|Makefile padrão dos tutoriais do p4lang - compilador .p4 e sobe topologia|
|[scan-block/documentacaoPratica.md](https://file+.vscode-resource.vscode-cdn.net/home/raf/GitRepositories/Estudos/IBN-p4/scan-block/documentacaoPratica.md)|Relatório da parte prática|

# ☱Como rodar?
--- 

### ☱Pré-requisitos--------------------------------------------------------------------------------
- Recomendo usar a vm própria do p4lang (já tem todos os utils pro Makefile), possui p4c, bhmv2 e mininet já instalados

### ☱Passo-a-passo--------------------------------------------------------------------------------

1. Compila o **.p4** e sobe a topologia:
    
    ```
    make run
    ```
    
1. Precisa abrir um novo terminal pra poder iniciar o controlador de intenções:
    
    ```
    python3 intent.py
    ```
    
    Mas é possivel mandar uma só intenção por vez, sem usar o chat do intent 
    
    ```
    python3 intent.py "bloquear h1 por 30 segundos"
    ```
    
1. (Opcional) Para observar o bloqueio acontecendo, sem usar o wireshark abre o xterm do h2 e roda o receive:
    
    ```
    mininet> xterm h2
    python3 receive.py
    ```
    
    Por último, disparar um scan (nmap) contra h2 e observar o tráfego parar quando o IP é bloqueado, segue o exemplo usado na apresentação
    ```
    nmap -n -Pn -sS --max-retries -p 1-100 10.0.2.2
    ```
- -n : Pular DNS
- -Pn Pula o ping que o nmap faz antes de começar o scan
- max-retries : reenvia so uma vez um pacote que não teve resposta

# ☱Intenções cobridas
----

| Frase (exemplo)                                  | Efeito                                                                                                                  |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `bloquear varreduras mais de 30`                 | Muda o limite de SYNs aceitos por janela                                                                                |
| `bloquear varreduras mais de 30 por 60 segundos` | Mesma coisa, mas os bloqueios só duram 60s                                                                              |
| `parar de bloquear varreduras`                   | desliga o detector  automático e zera os contadores e bloqueios                                                         |
| `bloquear h1`                                    | bloqueia manualmente o host h1 (até alguem desbloquear)                                                                 |
| `bloquear h1 por 30 segundos`                    | bloqueia h1 e libera automaticamente depois de 30s                                                                      |
| `liberar h1`                                     | remove o bloqueio manual de h1 e zera seus contadores (se o bloqueio automático estiver ligado, ele continua bloqueado) |
| `status`                                         | mostra o estado real do switch: detector, contagem de SYNs por host e regras já implementadas                           |

