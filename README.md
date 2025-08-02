# VPN Router Script

Este script Bash permite que você compartilhe sua conexão VPN (Virtual Private Network) com outros dispositivos em sua rede local. Isso é útil para rotear o tráfego de outros computadores através da sua VPN sem a necessidade de instalar e configurar o cliente VPN em cada um deles.

## Funcionalidades

- **Encaminhamento de IP (IP Forwarding):** Habilita o encaminhamento de pacotes no seu sistema para que ele possa atuar como um roteador.
- **NAT (Network Address Translation):** Utiliza `iptables` para mascarar o tráfego da sua rede local, fazendo com que ele pareça vir do seu próprio computador através da interface VPN.
- **Gerenciamento de Regras de Firewall:** Adiciona e remove as regras de `iptables` necessárias de forma segura, com backup e restauração.
- **Configuração Flexível:** Permite configurar as interfaces de rede via arquivo `.env`.
- **Logging Colorido:** Mensagens de log com cores para facilitar a leitura e depuração.
- **Verificação de Privilégios:** Garante que o script seja executado com as permissões necessárias.
- **Verificação de Status:** Permite verificar o status atual do roteamento e das regras do firewall.

## Pré-requisitos

- Um sistema operacional baseado em Linux (testado no Arch Linux, mas deve funcionar em outras distribuições como Ubuntu, Debian, Fedora).
- `iptables` instalado (geralmente vem pré-instalado).
- Cliente VPN configurado e funcionando (OpenVPN, WireGuard, etc.).
- Privilégios de `sudo`.

## Como Usar

### 1. Download do Script

Baixe o script `vpn-router.sh` e o arquivo de exemplo `.env.example` para um diretório de sua escolha.

```bash
git clone <URL_DO_REPOSITORIO> # Se estiver em um repositório
# Ou baixe os arquivos manualmente
```

### 2. Configuração

Crie uma cópia do arquivo `.env.example` e renomeie-o para `.env` no mesmo diretório do script `vpn-router.sh`:

```bash
cp .env.example .env
```

Edite o arquivo `.env` e configure as seguintes variáveis:

- `LAN_INTERFACE`: O nome da sua interface de rede local (ex: `enp0s3`, `eth0`, `wlan0`). Você pode descobrir o nome correto usando o comando `ip a` no terminal e procurando pela interface que tem um endereço IP na sua rede local (ex: `192.168.1.x`).
- `VPN_INTERFACE`: O nome da sua interface VPN (ex: `tun0`, `wg0`, `tap0`). Esta interface é criada pelo seu cliente VPN após a conexão ser estabelecida. Para descobrir o nome correto, conecte-se à sua VPN e execute `ip a` novamente. A nova interface que aparecer, geralmente com um IP da rede remota (ex: `10.8.0.x`), será a sua interface VPN.
- `LOG_LEVEL`: O nível de detalhe dos logs. Opções: `DEBUG`, `INFO` (padrão), `WARN`, `ERROR`.

Exemplo de `.env`:

```dotenv
LAN_INTERFACE=enp0s3
VPN_INTERFACE=tun0
LOG_LEVEL=INFO
```

### 3. Tornar o Script Executável

Conceda permissões de execução ao script:

```bash
chmod +x vpn-router.sh
```

### 4. Execução

Certifique-se de que sua conexão VPN esteja ativa antes de executar o script para habilitar o roteamento.

- **Habilitar Roteamento:**

  ```bash
  sudo ./vpn-router.sh enable
  ```

- **Desabilitar Roteamento:**

  ```bash
  sudo ./vpn-router.sh disable
  ```

- **Verificar Status:**

  ```bash
  sudo ./vpn-router.sh status
  ```

### 5. Configuração dos Dispositivos Clientes

Para que outros dispositivos na sua rede local utilizem a conexão VPN através do seu notebook, você precisará configurá-los para usar o seu notebook como gateway para a rede do escritório.

**Exemplo (Windows):**

Se a rede do seu escritório for `10.0.0.0/8` e o IP do seu notebook na rede local for `192.168.1.100`:

1. Abra o Prompt de Comando como Administrador.
2. Adicione uma rota estática:
   ```cmd
   route ADD 10.0.0.0 MASK 255.0.0.0 192.168.1.100 METRIC 1 IF <Interface_ID_da_sua_LAN>
   ```
   Substitua `<Interface_ID_da_sua_LAN>` pelo ID da interface de rede do seu PC Windows (você pode encontrar isso com `route print`).

**Observação:** A rota padrão (`0.0.0.0`) dos seus dispositivos clientes deve continuar apontando para o seu roteador doméstico para que o tráfego de internet geral não passe pela VPN, apenas o tráfego destinado à rede do escritório.

## Solução de Problemas

- **"Este script deve ser executado com privilégios de root."**: Use `sudo` antes do comando. Se estiver no Arch Linux e `sudo` não funcionar, certifique-se de que seu usuário está no grupo `wheel` (`sudo usermod -aG wheel $USER`).
- **"Interface LAN/VPN não encontrada."**: Verifique os nomes das interfaces no seu arquivo `.env` usando `ip a`.
- **Problemas de Conectividade:** Verifique o status do roteamento (`sudo ./vpn-router.sh status`) e as regras do `iptables` (`sudo iptables -L -v -n` e `sudo iptables -t nat -L -v -n`).

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo `LICENSE` para mais detalhes. (Se você pretende adicionar um arquivo LICENSE, caso contrário, remova esta linha).
