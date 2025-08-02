#!/bin/bash

# ==============================================================================
# VPN Router Script - Compartilhamento de Conexão VPN v2.2
# ==============================================================================
# Autor: Krisofferson Marini (com melhorias sugeridas)
# e-mail: ksmarini@gmail.com
# Versão: 2.2
# Licença: MIT
# Descrição: Script para compartilhar conexão VPN entre dispositivos na rede local,
#            com configurações externas e feedback visual colorido.
# ==============================================================================

set -euo pipefail # Modo strict: sai em caso de erro, variável não definida ou erro em pipe

# --- DEFINIÇÃO DE CORES E FUNÇÕES DE MENSAGEM ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

msg_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}
msg_success() {
  echo -e "${GREEN}[SUCESSO]${NC} $1"
}
msg_error() {
  echo -e "${RED}[ERRO]${NC} $1" >&2
}
msg_warn() {
  echo -e "${YELLOW}[AVISO]${NC} $1"
}

# --- CARREGAR CONFIGURAÇÕES ---
load_config() {
  msg_info "Carregando configurações..."
  if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
    msg_success "Arquivo .env carregado."
  else
    msg_error "Arquivo de configuração .env não encontrado. Crie um com as variáveis LAN_IF e VPN_IF."
    exit 1
  fi

  if [ -z "${LAN_IF:-}" ] || [ -z "${VPN_IF:-}" ]; then
    msg_error "As variáveis LAN_IF e VPN_IF devem estar definidas no arquivo .env."
    exit 1
  fi
}

# --- VERIFICAR PRIVILÉGIOS ---
check_privileges() {
  if [ "$(id -u)" -ne 0 ]; then
    msg_error "Este script precisa ser executado como root. Use 'sudo'."
    exit 1
  fi
}

# --- HABILITAR ROTEAMENTO ---
enable_routing() {
  msg_info "Ativando o roteamento..."

  # Ativa o encaminhamento de IP
  # sysctl -w net.ipv4.ip_forward=1 # Forma alternativa
  echo 1 >/proc/sys/net/ipv4/ip_forward
  msg_info "Encaminhamento de IP ativado."

  # Limpa regras anteriores para evitar duplicação (idempotência)
  msg_warn "Limpando regras de iptables existentes para este script..."
  iptables -t nat -D POSTROUTING -o "$VPN_IF" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "$LAN_IF" -o "$VPN_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$VPN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

  # Configura as regras de NAT e encaminhamento
  msg_info "Configurando regras de NAT e encaminhamento no iptables..."
  iptables -t nat -A POSTROUTING -o "$VPN_IF" -j MASQUERADE
  iptables -A FORWARD -i "$LAN_IF" -o "$VPN_IF" -j ACCEPT
  iptables -A FORWARD -i "$VPN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

  msg_success "Roteamento da LAN ($LAN_IF) para a VPN ($VPN_IF) ativado."
}

# --- DESABILITAR ROTEAMENTO ---
disable_routing() {
  msg_info "Desativando o roteamento..."

  # Remove as regras de iptables
  msg_info "Removendo regras de iptables..."
  iptables -t nat -D POSTROUTING -o "$VPN_IF" -j MASQUERADE
  iptables -D FORWARD -i "$LAN_IF" -o "$VPN_IF" -j ACCEPT
  iptables -D FORWARD -i "$VPN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

  # Desativa o encaminhamento de IP (opcional, mais seguro)
  echo 0 >/proc/sys/net/ipv4/ip_forward
  msg_info "Encaminhamento de IP desativado."

  msg_success "Roteamento desativado."
}

# --- MOSTRAR STATUS ---
show_status() {
  msg_info "Verificando status do roteamento..."

  local ip_forward
  ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)

  if [ "$ip_forward" = "1" ]; then
    msg_info "Encaminhamento de IP: ${GREEN}ATIVO${NC}"
  else
    msg_info "Encaminhamento de IP: ${RED}INATIVO${NC}"
  fi

  msg_info "Verificando regras de iptables para $VPN_IF e $LAN_IF:"
  if iptables -t nat -C POSTROUTING -o "$VPN_IF" -j MASQUERADE &>/dev/null; then
    echo -e " -> Regra de NAT (POSTROUTING): ${GREEN}ATIVO${NC}"
  else
    echo -e " -> Regra de NAT (POSTROUTING): ${RED}INATIVO${NC}"
  fi

  if iptables -C FORWARD -i "$LAN_IF" -o "$VPN_IF" -j ACCEPT &>/dev/null; then
    echo -e " -> Regra de FORWARD (LAN -> VPN): ${GREEN}ATIVO${NC}"
  else
    echo -e " -> Regra de FORWARD (LAN -> VPN): ${RED}INATIVO${NC}"
  fi
}

# --- MENSAGEM DE USO ---
usage() {
  echo -e "${BLUE}Uso:${NC} sudo $0 {enable|disable|status}"
  echo -e "  ${YELLOW}enable${NC}   : Ativa o compartilhamento da conexão VPN."
  echo -e "  ${YELLOW}disable${NC}  : Desativa o compartilhamento."
  echo -e "  ${YELLOW}status${NC}   : Mostra o status atual do roteamento."
}

# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================
main() {
  check_privileges
  load_config

  case "${1:-status}" in # Define 'status' como padrão se nenhum argumento for passado
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
    exit 1
    ;;
  esac
}

# Executa a função principal com os argumentos passados para o script
main "$@"
