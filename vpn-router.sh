#!/bin/bash

# ==============================================================================
# VPN Router Script - Compartilhamento de Conexão VPN
# ==============================================================================
# Autor: Krisofferson Marini
# e-mail: ksmarini@gmail.com
# Versão: 2.0
# Licença: MIT
# Descrição: Script para compartilhar conexão VPN entre dispositivos na rede local
# ==============================================================================

set -euo pipefail # Modo strict: sai em caso de erro, variável não definida ou pipe failure

# Cores para logging
readonly RED=\'\\033[031m\'
readonly GREEN=\'\\033[032m\'
readonly YELLOW=\'\\033[133m\'
readonly BLUE=\'\\033[034m\'
readonly NC=\'\\033[0m\' # No Color

# Configurações padrão
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/.env"
readonly BACKUP_FILE="/tmp/iptables_before_vpn_routing_$(date +%s).rules"

# Variáveis de configuração (podem ser sobrescritas pelo .env)
LAN_INTERFACE="${LAN_INTERFACE:-enp0s3}"
VPN_INTERFACE="${VPN_INTERFACE:-tun0}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

# ==============================================================================
# FUNÇÕES DE LOGGING
# ==============================================================================

log_info() {
  [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO)$ ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARN)$ ]] && echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
  [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${BLUE}[DEBUG]${NC} $1"
}

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

# Carrega configurações do arquivo .env se existir
load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    log_debug "Carregando configurações de $CONFIG_FILE"
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    log_info "Configurações carregadas do arquivo .env"
  else
    log_warn "Arquivo .env não encontrado. Usando configurações padrão."
    log_info "Crie um arquivo .env no mesmo diretório do script para personalizar as configurações."
  fi
}

# Verifica se o script está sendo executado com privilégios adequados
check_privileges() {
  if [[ $EUID -ne 0 ]]; then
    log_error "Este script deve ser executado com privilégios de root."

    # Detecta o grupo administrativo baseado na distribuição
    if command -v pacman >/dev/null 2>&1; then
      # Arch Linux usa o grupo \'wheel\'
      log_error "No Arch Linux, adicione seu usuário ao grupo \'wheel\' e use \'sudo\'."
      log_error "Comando: sudo usermod -aG wheel \\\$USER"
    else
      # Debian/Ubuntu e outras distribuições usam \'sudo\'
      log_error "Adicione seu usuário ao grupo \'sudo\' se necessário."
    fi

    log_error "Uso: sudo $0 [enable|disable|status]"
    exit 1
  fi
}

# Verifica se as interfaces de rede existem
check_interfaces() {
  log_debug "Verificando interfaces de rede..."

  if ! ip link show "$LAN_INTERFACE" >/dev/null 2>&1; then
    log_error "Interface LAN \'$LAN_INTERFACE\' não encontrada."
    log_error "Interfaces disponíveis:"
    ip link show | grep -E \'^[0-9]+:\' | awk -F\': \' \'{print "  - " $2}\' | sed \'s/@.*//\'
    return 1
  fi

  if ! ip link show "$VPN_INTERFACE" >/dev/null 2>&1; then
    log_error "Interface VPN \'$VPN_INTERFACE\' não encontrada."
    log_error "Certifique-se de que a VPN está conectada."
    log_error "Interfaces disponíveis:"
    ip link show | grep -E \'^[0-9]+:\' | awk -F\': \' \'{print "  - " $2}\' | sed \'s/@.*//\'
    return 1
  fi

  log_debug "Interfaces verificadas com sucesso"
}

# Executa comando com tratamento de erro
run_command() {
  local cmd="$1"
  local description="$2"

  log_debug "Executando: $cmd"

  if eval "$cmd" >/dev/null 2>&1; then
    log_info "$description [OK]"
    return 0
  else
    log_error "$description [FALHA]"
    return 1
  fi
}

# Verifica se uma regra do iptables existe
rule_exists() {
  local table="$1"
  local chain="$2"
  local rule="$3"

  # Tenta verificar a regra. O '|| true' garante que o 'set -e' não saia se a regra não existir.
  if [[ "$table" == "filter" ]]; then
    iptables -C "$chain" $rule 2>/dev/null || true
  else
    iptables -t "$table" -C "$chain" $rule 2>/dev/null || true
  fi

  # Retorna o status da verificação (0 se a regra existe, 1 se não)
  # O $? é o código de saída do último comando (iptables -C)
  return $?
}

# Adiciona regra do iptables se não existir
add_rule_if_not_exists() {
  local table="$1"
  local chain="$2"
  local rule="$3"
  local description="$4"

  if rule_exists "$table" "$chain" "$rule"; then
    log_info "$description [JÁ EXISTE]"
  else
    if [[ "$table" == "filter" ]]; then
      if iptables -A "$chain" $rule; then
        log_info "$description [ADICIONADA]"
      else
        log_error "$description [FALHA]"
        return 1
      fi
    else
      if iptables -t "$table" -A "$chain" $rule; then
        log_info "$description [ADICIONADA]"
      else
        log_error "$description [FALHA]"
        return 1
      fi
    fi
  fi
}

# ==============================================================================
# FUNÇÕES PRINCIPAIS
# ==============================================================================

# Exibe informações de uso
usage() {
  cat <<EOF
Uso: $0 [enable|disable|status]

COMANDOS:
  enable   - Ativa o roteamento da VPN e NAT
  disable  - Desativa o roteamento da VPN e NAT
  status   - Mostra o status atual do roteamento

CONFIGURAÇÃO:
  Crie um arquivo .env no mesmo diretório do script com as seguintes variáveis:
  
  LAN_INTERFACE=enp0s3     # Interface da rede local
  VPN_INTERFACE=tun0       # Interface da VPN
  LOG_LEVEL=INFO           # Nível de log (DEBUG, INFO, WARN, ERROR)

EXEMPLOS:
  sudo $0 enable           # Ativa o roteamento
  sudo $0 disable          # Desativa o roteamento
  sudo $0 status           # Verifica status

Para descobrir suas interfaces de rede, use: ip a

EOF
  exit 1
}

# Mostra o status atual do roteamento
show_status() {
  echo "========================================"
  echo "STATUS DO ROTEAMENTO VPN"
  echo "========================================"

  # Verifica IP forwarding
  local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
  if [[ "$ip_forward" == "1" ]]; then
    log_info "IP Forwarding: ATIVADO"
  else
    log_warn "IP Forwarding: DESATIVADO"
  fi

  # Verifica interfaces
  echo ""
  echo "Interfaces configuradas:"
  echo "  LAN: $LAN_INTERFACE"
  echo "  VPN: $VPN_INTERFACE"

  echo ""
  echo "Status das interfaces:"
  if ip link show "$LAN_INTERFACE" >/dev/null 2>&1; then
    local lan_ip=$(ip addr show "$LAN_INTERFACE" | grep -oP \'inet \\K[\\d.]+\' | head -1)
    log_info "LAN ($LAN_INTERFACE): UP - IP: ${lan_ip:-N/A}"
  else
    log_error "LAN ($LAN_INTERFACE): NÃO ENCONTRADA"
  fi

  if ip link show "$VPN_INTERFACE" >/dev/null 2>&1; then
    local vpn_ip=$(ip addr show "$VPN_INTERFACE" | grep -oP \'inet \\K[\\d.]+\' | head -1)
    log_info "VPN ($VPN_INTERFACE): UP - IP: ${vpn_ip:-N/A}"
  else
    log_error "VPN ($VPN_INTERFACE): NÃO ENCONTRADA"
  fi

  # Verifica regras do iptables
  echo ""
  echo "Regras do iptables:"

  if rule_exists "nat" "POSTROUTING" "-o $VPN_INTERFACE -j MASQUERADE"; then
    log_info "Regra MASQUERADE: PRESENTE"
  else
    log_warn "Regra MASQUERADE: AUSENTE"
  fi

  if rule_exists "filter" "FORWARD" "-i $LAN_INTERFACE -o $VPN_INTERFACE -j ACCEPT"; then
    log_info "Regra FORWARD (LAN→VPN): PRESENTE"
  else
    log_warn "Regra FORWARD (LAN→VPN): AUSENTE"
  fi

  if rule_exists "filter" "FORWARD" "-i $VPN_INTERFACE -o $LAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT"; then
    log_info "Regra FORWARD (VPN→LAN): PRESENTE"
  else
    log_warn "Regra FORWARD (VPN→LAN): AUSENTE"
  fi

  echo "========================================"
}

# Ativa o roteamento da VPN
enable_routing() {
  echo "========================================"
  echo "ATIVANDO ROTEAMENTO VPN"
  echo "========================================"
  echo "Interface LAN: $LAN_INTERFACE"
  echo "Interface VPN: $VPN_INTERFACE"
  echo "========================================"

  # Verifica interfaces antes de prosseguir
  if ! check_interfaces; then
    log_error "Falha na verificação das interfaces. Abortando."
    return 1
  fi

  # Habilita IP forwarding
  log_info "Habilitando IP forwarding..."
  if ! run_command "sysctl -w net.ipv4.ip_forward=1" "IP forwarding"; then
    log_error "Falha ao habilitar IP forwarding"
    return 1
  fi

  # Salva regras atuais do iptables
  log_info "Salvando regras atuais do iptables..."
  if ! iptables-save >"$BACKUP_FILE"; then
    log_error "Falha ao salvar regras do iptables"
    return 1
  fi
  log_info "Backup salvo em: $BACKUP_FILE"

  # Adiciona regras do iptables
  log_info "Configurando regras do iptables..."

  add_rule_if_not_exists "nat" "POSTROUTING" "-o $VPN_INTERFACE -j MASQUERADE" \
    "Regra MASQUERADE na interface VPN"

  add_rule_if_not_exists "filter" "FORWARD" "-i $LAN_INTERFACE -o $VPN_INTERFACE -j ACCEPT" \
    "Regra FORWARD (LAN → VPN)"

  add_rule_if_not_exists "filter" "FORWARD" "-i $VPN_INTERFACE -o $LAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT" \
    "Regra FORWARD (VPN → LAN)"

  echo "========================================"
  log_info "ROTEAMENTO VPN ATIVADO COM SUCESSO!"
  echo "========================================"

  # Mostra informações úteis
  echo ""
  echo "PRÓXIMOS PASSOS:"
  echo "1. Configure os dispositivos da rede para usar este computador como gateway"
  echo "2. Configure rotas estáticas nos dispositivos para a rede do escritório"
  echo ""
  echo "Para verificar o status: sudo $0 status"
}

# Desativa o roteamento da VPN
disable_routing() {
  echo "========================================"
  echo "DESATIVANDO ROTEAMENTO VPN"
  echo "========================================"

  # Desabilita IP forwarding
  log_info "Desabilitando IP forwarding..."
  run_command "sysctl -w net.ipv4.ip_forward=0" "IP forwarding"

  # Restaura regras do iptables
  log_info "Restaurando regras originais do iptables..."

  # Procura pelo backup mais recente
  local latest_backup
  latest_backup=$(find /tmp -name "iptables_before_vpn_routing_*.rules" -type f 2>/dev/null | sort -r | head -1)

  if [[ -n "$latest_backup" && -f "$latest_backup" ]]; then
    if iptables-restore <"$latest_backup"; then
      log_info "Regras restauradas de: $latest_backup"
      rm -f "$latest_backup"
      log_debug "Arquivo de backup removido"
    else
      log_error "Falha ao restaurar regras do iptables"
      log_error "Backup mantido em: $latest_backup"
      return 1
    fi
  else
    log_warn "Backup não encontrado. Tentando remoção manual das regras..."

    # Remove regras específicas (pode falhar silenciosamente)
    iptables -t nat -D POSTROUTING -o "$VPN_INTERFACE" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$LAN_INTERFACE" -o "$VPN_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VPN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    log_info "Tentativa de remoção manual concluída"
  fi

  echo "========================================"
  log_info "ROTEAMENTO VPN DESATIVADO COM SUCESSO!"
  echo "========================================"
}

# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================

# A função principal agora recebe os argumentos diretamente
main() {
  # Carrega configurações
  load_config

  # Verifica privilégios
  check_privileges

  # Processa argumentos
  case "${1:-}" in
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
