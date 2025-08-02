#!/bin/bash

# ==============================================================================
# VPN Router Script v2.1 - Compartilhamento de Conexão VPN
# ==============================================================================
# Autor: Krisofferson Marini
# e-mail: ksmarini@gmail.com
# Versão: 2.1
# Licença: MIT
# Descrição: Script para compartilhar conexão VPN. Carrega as interfaces de
#            um arquivo .env localizado na mesma pasta.
# ==============================================================================

# Modo estrito: sai em caso de erro, variável não definida ou erro em pipe.
set -euo pipefail

# ==============================================================================
# CARREGAR CONFIGURAÇÕES EXTERNAS
# ==============================================================================

# Define o caminho absoluto para o diretório do script
# Isso garante que o .env seja encontrado independentemente de onde o script é chamado
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

# Verifica se o arquivo .env existe
if [ ! -f "$ENV_FILE" ]; then
  echo "ERRO: Arquivo de configuração '$ENV_FILE' não encontrado." >&2
  echo "Por favor, crie um arquivo .env com as variáveis VPN_INTERFACE e LAN_INTERFACE." >&2
  exit 1
fi

# Carrega as variáveis do arquivo .env
# O comando 'source' (ou '.') executa o arquivo no shell atual, importando suas variáveis
source "$ENV_FILE"

# Valida se as variáveis foram carregadas corretamente do .env
if [ -z "${VPN_INTERFACE:-}" ] || [ -z "${LAN_INTERFACE:-}" ]; then
  echo "ERRO: As variáveis VPN_INTERFACE e/ou LAN_INTERFACE não estão definidas no arquivo .env." >&2
  echo "Verifique o conteúdo de '$ENV_FILE'." >&2
  exit 1
fi

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

# Exibe como usar o script
usage() {
  echo "Uso: sudo $0 [enable|disable|status]"
  echo "  enable : Ativa o roteamento da LAN para a VPN."
  echo "  disable: Desativa o roteamento."
  echo "  status : Verifica o status atual do roteamento."
  exit 1
}

# Verifica se o script está sendo executado como root
check_privileges() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: Este script precisa ser executado com privilégios de root (use sudo)." >&2
    exit 1
  fi
}

# Ativa o roteamento
enable_routing() {
  echo "Ativando o roteamento da VPN..."
  echo "LAN ($LAN_INTERFACE) -> VPN ($VPN_INTERFACE)"

  # Limpa regras anteriores para evitar duplicação (idempotência)
  disable_routing >/dev/null 2>&1

  # Ativa o encaminhamento de IP no kernel
  echo 1 >/proc/sys/net/ipv4/ip_forward

  # Adiciona as regras de firewall para NAT (mascaramento)
  # Permite que pacotes da LAN saiam pela interface da VPN com o IP dela
  iptables -t nat -A POSTROUTING -o "$VPN_INTERFACE" -j MASQUERADE
  # Permite o tráfego de volta da VPN para a LAN
  iptables -A FORWARD -i "$VPN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  # Permite o tráfego da LAN para a VPN
  iptables -A FORWARD -i "$LAN_INTERFACE" -o "$VPN_INTERFACE" -j ACCEPT

  echo "Roteamento ativado com sucesso."
}

# Desativa o roteamento
disable_routing() {
  echo "Desativando o roteamento da VPN..."

  # Remove as regras de firewall de forma segura
  # O '-C' verifica se a regra existe antes de tentar deletar, evitando erros.
  iptables -t nat -C POSTROUTING -o "$VPN_INTERFACE" -j MASQUERADE &>/dev/null &&
    iptables -t nat -D POSTROUTING -o "$VPN_INTERFACE" -j MASQUERADE
  iptables -C FORWARD -i "$VPN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT &>/dev/null &&
    iptables -C FORWARD -i "$VPN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -C FORWARD -i "$LAN_INTERFACE" -o "$VPN_INTERFACE" -j ACCEPT &>/dev/null &&
    iptables -C FORWARD -i "$LAN_INTERFACE" -o "$VPN_INTERFACE" -j ACCEPT

  # Desativa o encaminhamento de IP no kernel (opcional, mas boa prática)
  echo 0 >/proc/sys/net/ipv4/ip_forward

  echo "Roteamento desativado."
}

# Mostra o status atual
show_status() {
  echo "================== Status do Roteamento VPN =================="
  echo "Interface da VPN: $VPN_INTERFACE"
  echo "Interface da LAN: $LAN_INTERFACE"
  echo ""

  local ip_forward
  ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)

  if [ "$ip_forward" -eq 1 ]; then
    echo "Kernel IP Forwarding: ATIVADO"
  else
    echo "Kernel IP Forwarding: DESATIVADO"
  fi

  echo ""
  echo "Regras de Firewall (iptables) relevantes:"
  # O comando grep retorna um status de erro se não encontrar nada, o '|| true' evita que o 'set -e' pare o script
  (iptables -t nat -L POSTROUTING -n -v | grep "MASQUERADE.*$VPN_INTERFACE" &&
    iptables -L FORWARD -n -v | grep "$LAN_INTERFACE.*$VPN_INTERFACE") || true

  if iptables -t nat -C POSTROUTING -o "$VPN_INTERFACE" -j MASQUERADE &>/dev/null; then
    echo -e "\nResultado: O roteamento parece estar ATIVO."
  else
    echo -e "\nResultado: O roteamento parece estar INATIVO."
  fi
  echo "=============================================================="
}

# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================

main() {
  # Verifica privilégios
  check_privileges

  # Processa argumentos da linha de comando
  # Se nenhum argumento for passado, o padrão é 'status'
  case "${1:-status}" in
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

# Executa a função principal com todos os argumentos passados para o script
main "$@"
