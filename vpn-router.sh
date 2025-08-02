#!/bin/bash
# ==============================================================================
# VPN Router Script - Compartilhamento de Conexão VPN
# ==============================================================================
# Autor:      Krisofferson Marini
# e-mail:     ksmarini@gmail.com
# Versão:     2.5
# Licença:    MIT
# Descrição:  Script para compartilhar uma conexão VPN (ex: tun0) com outros
#             dispositivos em uma rede local (ex: eth0).
#             Requer privilégios de root para manipular o roteamento e o firewall.
# ==============================================================================

# MODO STRICT: Sai imediatamente se um comando falhar (-e), se uma variável
# não definida for usada (-u), ou se um comando em um pipe falhar (-o pipefail).
set -euo pipefail

# ==============================================================================
# CONFIGURAÇÃO - MODIFIQUE ESTAS VARIÁVEIS
# ==============================================================================
# Para descobrir os nomes das suas interfaces, use o comando: ip addr

# Interface da sua VPN (geralmente 'tun0' para OpenVPN/WireGuard)
VPN_IFACE="tunsnx"

# Interface da sua rede local (pode ser 'eth0', 'enp3s0', 'wlan0', etc.)
LAN_IFACE="wlp0s20f3"

# Sub-rede da sua rede local. O script tentará detectar automaticamente,
# mas você pode definir manualmente se a detecção falhar.
# Exemplo: LAN_SUBNET="192.168.1.0/24"
LAN_SUBNET=""

# ==============================================================================
# VARIÁVEIS GLOBAIS (Não modificar)
# ==============================================================================
# Cores para o output
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_NC='\033[0m' # Sem Cor

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

# Imprime mensagens de log com cores
log() {
  local color="$1"
  local message="$2"
  printf "${color}%s${C_NC}\n" "$message"
}

# Verifica se o script está sendo executado como root
check_privileges() {
  if [ "$(id -u)" -ne 0 ]; then
    log "$C_RED" "ERRO: Este script precisa ser executado com privilégios de root (use sudo)."
    exit 1
  fi
}

# Detecta a sub-rede da LAN se não estiver definida
detect_subnet() {
  if [ -z "$LAN_SUBNET" ]; then
    log "$C_BLUE" "Tentando detectar a sub-rede para a interface ${LAN_IFACE}..."
    # Usa `ip` para obter o endereço CIDR da interface e `grep` para filtrar a linha correta
    LAN_SUBNET=$(ip -4 addr show "${LAN_IFACE}" | grep -oP 'inet \K[\d.]+\/\d+' | head -n 1)
    if [ -z "$LAN_SUBNET" ]; then
      log "$C_RED" "ERRO: Não foi possível detectar a sub-rede para ${LAN_IFACE}."
      log "$C_YELLOW" "Por favor, defina a variável LAN_SUBNET manualmente no script."
      exit 1
    fi
    log "$C_GREEN" "Sub-rede detectada: ${LAN_SUBNET}"
  fi
}

# Exibe como usar o script
usage() {
  printf "Uso: %s [comando]\n\n" "$0"
  printf "Comandos:\n"
  printf "  ${C_GREEN}enable${C_NC}   - Ativa o roteamento da LAN para a VPN.\n"
  printf "  ${C_RED}disable${C_NC}  - Desativa o roteamento e limpa as regras.\n"
  printf "  ${C_YELLOW}status${C_NC}   - Mostra o estado atual do roteamento e das regras.\n"
  exit 1
}

# ==============================================================================
# FUNÇÕES PRINCIPAIS
# ==============================================================================

# Ativa o roteamento e as regras de firewall
enable_routing() {
  log "$C_BLUE" "Ativando o compartilhamento de VPN..."

  # 1. Ativa o encaminhamento de IP no kernel
  log "$C_BLUE" "[1/3] Ativando encaminhamento de IP (net.ipv4.ip_forward=1)..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # 2. Adiciona a regra de NAT (MASQUERADE)
  # Esta regra faz com que o tráfego da LAN pareça vir da interface VPN
  log "$C_BLUE" "[2/3] Adicionando regra de NAT (MASQUERADE) via iptables..."
  # -C (check) verifica se a regra já existe para evitar duplicatas
  if ! iptables -t nat -C POSTROUTING -o "${VPN_IFACE}" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -o "${VPN_IFACE}" -j MASQUERADE
  else
    log "$C_YELLOW" "A regra de MASQUERADE já existe. Nenhuma ação necessária."
  fi

  # 3. Adiciona as regras de encaminhamento (FORWARD)
  # Permite que pacotes da LAN sejam encaminhados para a VPN e vice-versa
  log "$C_BLUE" "[3/3] Adicionando regras de encaminhamento (FORWARD) via iptables..."
  # Regra para permitir o tráfego da LAN para a VPN
  if ! iptables -C FORWARD -i "${LAN_IFACE}" -o "${VPN_IFACE}" -j ACCEPT &>/dev/null; then
    iptables -A FORWARD -i "${LAN_IFACE}" -o "${VPN_IFACE}" -j ACCEPT
  else
    log "$C_YELLOW" "A regra de FORWARD (LAN -> VPN) já existe."
  fi

  # Regra para permitir o tráfego de volta (conexões estabelecidas)
  if ! iptables -C FORWARD -i "${VPN_IFACE}" -o "${LAN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT &>/dev/null; then
    iptables -A FORWARD -i "${VPN_IFACE}" -o "${LAN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT
  else
    log "$C_YELLOW" "A regra de FORWARD (VPN -> LAN, established) já existe."
  fi

  log "$C_GREEN" "Roteamento ativado com sucesso!"
  log "$C_YELLOW" "Dispositivos na rede ${LAN_SUBNET} agora podem usar a VPN."
}

# Desativa o roteamento e remove as regras de firewall
disable_routing() {
  log "$C_RED" "Desativando o compartilhamento de VPN..."

  # 1. Remove as regras de firewall (na ordem inversa da adição)
  log "$C_RED" "[1/3] Removendo regras de encaminhamento (FORWARD)..."
  # -C (check) garante que só tentamos remover regras que existem, evitando erros
  if iptables -C FORWARD -i "${VPN_IFACE}" -o "${LAN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT &>/dev/null; then
    iptables -D FORWARD -i "${VPN_IFACE}" -o "${LAN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi
  if iptables -C FORWARD -i "${LAN_IFACE}" -o "${VPN_IFACE}" -j ACCEPT &>/dev/null; then
    iptables -D FORWARD -i "${LAN_IFACE}" -o "${VPN_IFACE}" -j ACCEPT
  fi

  # 2. Remove a regra de NAT
  log "$C_RED" "[2/3] Removendo regra de NAT (MASQUERADE)..."
  if iptables -t nat -C POSTROUTING -o "${VPN_IFACE}" -j MASQUERADE &>/dev/null; then
    iptables -t nat -D POSTROUTING -o "${VPN_IFACE}" -j MASQUERADE
  fi

  # 3. Desativa o encaminhamento de IP no kernel
  # Apenas desativamos se nenhum outro script precisar dele.
  # É mais seguro deixar ativado se não tiver certeza. Para este uso, vamos desativar.
  log "$C_RED" "[3/3] Desativando encaminhamento de IP (net.ipv4.ip_forward=0)..."
  sysctl -w net.ipv4.ip_forward=0 >/dev/null

  log "$C_GREEN" "Roteamento desativado e regras limpas com sucesso!"
}

# Mostra o status atual
show_status() {
  log "$C_BLUE" "Verificando status do roteamento VPN..."

  # Verifica o encaminhamento de IP
  local ip_forward
  ip_forward=$(sysctl -n net.ipv4.ip_forward)
  if [ "$ip_forward" -eq 1 ]; then
    log "$C_GREEN" "Encaminhamento de IP está ATIVADO."
  else
    log "$C_RED" "Encaminhamento de IP está DESATIVADO."
  fi

  # Verifica as regras do iptables
  log "$C_BLUE" "Verificando regras de iptables..."
  local nat_rule_exists=false
  local forward_lan_vpn_exists=false
  local forward_vpn_lan_exists=false

  if iptables -t nat -C POSTROUTING -o "${VPN_IFACE}" -j MASQUERADE &>/dev/null; then
    nat_rule_exists=true
    log "$C_GREEN" "-> Regra de NAT (MASQUERADE) para ${VPN_IFACE}: PRESENTE"
  else
    log "$C_YELLOW" "-> Regra de NAT (MASQUERADE) para ${VPN_IFACE}: AUSENTE"
  fi

  if iptables -C FORWARD -i "${LAN_IFACE}" -o "${VPN_IFACE}" -j ACCEPT &>/dev/null; then
    forward_lan_vpn_exists=true
    log "$C_GREEN" "-> Regra de FORWARD (${LAN_IFACE} -> ${VPN_IFACE}): PRESENTE"
  else
    log "$C_YELLOW" "-> Regra de FORWARD (${LAN_IFACE} -> ${VPN_IFACE}): AUSENTE"
  fi

  if iptables -C FORWARD -i "${VPN_IFACE}" -o "${LAN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT &>/dev/null; then
    forward_vpn_lan_exists=true
    log "$C_GREEN" "-> Regra de FORWARD (Conexões estabelecidas): PRESENTE"
  else
    log "$C_YELLOW" "-> Regra de FORWARD (Conexões estabelecidas): AUSENTE"
  fi

  echo # Linha em branco para espaçamento

  if $nat_rule_exists && $forward_lan_vpn_exists && $forward_vpn_lan_exists && [ "$ip_forward" -eq 1 ]; then
    log "$C_GREEN" "Status Geral: ATIVO. O compartilhamento de VPN parece estar funcionando."
  else
    log "$C_RED" "Status Geral: INATIVO. O compartilhamento de VPN não está totalmente configurado."
  fi
}

# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================
main() {
  check_privileges
  detect_subnet

  case "${1:-status}" in # O padrão é 'status' se nenhum argumento for passado
  enable)
    enable_routing
    ;;
  disable)
    disable_routing
    ;;
  status)
    show_status
    ;;
  *)
    usage
    ;;
  esac
}

# Executa a função principal com os argumentos passados para o script
main "$@"
