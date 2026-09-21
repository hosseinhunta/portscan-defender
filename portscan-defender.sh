#!/bin/bash
# ============================================================================
# PortScan Defender - Linux
# ============================================================================
# Detects and blocks inbound port scans via nftables.
# Debian 11+, Ubuntu 20.04+ compatible.
#
# Architecture:
#   - nftables kernel sets for blocking (auto-expiring temp bans)
#   - journalctl for real-time log ingestion
#   - systemd for lifecycle management
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${PSD_CONFIG:-$SCRIPT_DIR/portscan-defender.conf}"

NFT_TABLE="portscan_defender"
NFT_FAMILY="inet"
NFT_CHAIN="input"
SET_TEMP="temp_block"
SET_PERM="perm_block"
SET_WL_IP="whitelist_ips"
SET_WL_PORT="whitelist_ports"
LOG_PREFIX="PSD:"

# ---------------------------------------------------------------------------
# Load configuration
# ---------------------------------------------------------------------------
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Safe defaults
: "${DETECTION_WINDOW:=10}"
: "${PORT_THRESHOLD:=15}"
: "${RATE_THRESHOLD:=25}"
: "${SYN_THRESHOLD:=5}"
: "${TEMP_BLOCK_SECONDS:=3600}"
: "${REPEAT_WINDOW_SECONDS:=86400}"
: "${POLL_INTERVAL:=5}"
: "${MAX_BLOCKED_IPS:=1000}"
: "${LOG_FILE:=/var/log/portscan-defender/defender.log}"
: "${STATE_FILE:=/var/lib/portscan-defender/state.tsv}"
: "${PORT_WHITELIST_FILE:=$SCRIPT_DIR/port_whitelist.txt}"
: "${LOG_RATE_LIMIT:=2000}"
: "${ENABLE_SYN_DETECTION:=1}"

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
declare -A PORT_WHITELIST=()
declare -A INCIDENTS=()
declare -A PERMANENT=()
declare -A DETECTION_HISTORY=()
RUNNING=true

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf '%s [%s] %s\n' "$ts" "$level" "$msg" | tee -a "$LOG_FILE" >&2 || true
}

log_setup() {
    mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATE_FILE")"
    chmod 750 "$(dirname "$LOG_FILE")" "$(dirname "$STATE_FILE")" 2>/dev/null || true
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat -c '%s' "$LOG_FILE" 2>/dev/null || echo 0)
        if (( size > 52428800 )); then
            mv "$LOG_FILE" "$LOG_FILE.old" 2>/dev/null || true
        fi
    fi
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# IP validation & CIDR matching (pure bash)
# ---------------------------------------------------------------------------
is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local IFS='.'
    local parts=($ip)
    local p
    for p in "${parts[@]}"; do
        (( 10#$p >= 0 && 10#$p <= 255 )) || return 1
    done
    return 0
}

ipv4_to_int() {
    local a b c d
    IFS='.' read -r a b c d <<< "$1"
    echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}

ip_in_cidr() {
    local ip="$1" cidr="$2"
    [[ "$cidr" != */* ]] && cidr="$cidr/32"
    local network="${cidr%/*}"
    local prefix="${cidr#*/}"

    is_valid_ipv4 "$ip"      || return 1
    is_valid_ipv4 "$network" || return 1

    local ip_int net_int mask
    ip_int=$(ipv4_to_int "$ip")
    net_int=$(ipv4_to_int "$network")

    if   (( prefix <= 0  )); then mask=0
    elif (( prefix >= 32 )); then mask=$(( 0xFFFFFFFF ))
    else mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi

    (( (ip_int & mask) == (net_int & mask) ))
}

is_ip_whitelisted() {
    local ip="$1"
    is_valid_ipv4 "$ip" || return 1

    # Always protect multicast/reserved
    local first="${ip%%.*}"
    (( 10#$first >= 224 )) && return 0

    local cidr
    for cidr in "${IP_WHITELIST[@]}"; do
        ip_in_cidr "$ip" "$cidr" && return 0
    done
    return 1
}

is_interesting_source() {
    local ip="$1"
    is_valid_ipv4 "$ip" || return 1
    [[ "$ip" == "0.0.0.0" ]] && return 1
    is_ip_whitelisted "$ip" && return 1
    return 0
}

# ---------------------------------------------------------------------------
# Port whitelist
# ---------------------------------------------------------------------------
load_port_whitelist() {
    PORT_WHITELIST=()
    [[ ! -f "$PORT_WHITELIST_FILE" ]] && {
        log WARN "Port whitelist not found: $PORT_WHITELIST_FILE"
        return
    }
    local line p start end
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(echo "$line" | tr -d '[:space:]')"
        [[ -z "$line" ]] && continue
        if [[ "$line" == *-* ]]; then
            start="${line%-*}"; end="${line#*-}"
            [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]] || continue
            for (( p=start; p<=end; p++ )); do PORT_WHITELIST[$p]=1; done
        else
            [[ "$line" =~ ^[0-9]+$ ]] || continue
            (( line >= 1 && line <= 65535 )) && PORT_WHITELIST[$line]=1
        fi
    done < "$PORT_WHITELIST_FILE"
    log INFO "Loaded ${#PORT_WHITELIST[@]} whitelisted ports"
}

compact_ports_to_ranges() {
    local -a ports
    mapfile -t ports < <(printf '%s\n' "$@" | sort -n | uniq)
    [[ ${#ports[@]} -eq 0 ]] && return 0

    local start="${ports[0]}" prev="${ports[0]}" p
    local -a ranges=()
    for p in "${ports[@]:1}"; do
        if (( p == prev + 1 )); then
            prev="$p"
        else
            [[ "$start" == "$prev" ]] && ranges+=("$start") || ranges+=("$start-$prev")
            start="$p"; prev="$p"
        fi
    done
    [[ "$start" == "$prev" ]] && ranges+=("$start") || ranges+=("$start-$prev")
    printf '%s\n' "${ranges[@]}"
}

# ---------------------------------------------------------------------------
# nftables management
# ---------------------------------------------------------------------------
nft_setup() {
    nft add table "$NFT_FAMILY" "$NFT_TABLE" 2>/dev/null || true

    nft add set "$NFT_FAMILY" "$NFT_TABLE" "$SET_WL_IP" \
        '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
    nft add set "$NFT_FAMILY" "$NFT_TABLE" "$SET_WL_PORT" \
        '{ type inet_service; flags interval; }' 2>/dev/null || true
    nft add set "$NFT_FAMILY" "$NFT_TABLE" "$SET_TEMP" \
        '{ type ipv4_addr; flags timeout; }' 2>/dev/null || true
    nft add set "$NFT_FAMILY" "$NFT_TABLE" "$SET_PERM" \
        '{ type ipv4_addr; }' 2>/dev/null || true

    nft add chain "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" \
        '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || true

    # Install filter rules once (idempotent via comment tag)
    if nft -a list chain "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" 2>/dev/null | \
            grep -q 'comment "psd-log"'; then
        log INFO "Filter rules already installed"
    else
        # 1) Always accept whitelisted IPs (never blocked, never logged)
        nft add rule "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" \
            ip saddr "@$SET_WL_IP" accept comment "psd-wl"

        # 2) Drop permanent blocks
        nft add rule "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" \
            ip saddr "@$SET_PERM" drop comment "psd-perm"

        # 3) Drop temporary blocks
        nft add rule "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" \
            ip saddr "@$SET_TEMP" drop comment "psd-temp"

        # 4) Log new TCP connections to non-whitelisted ports
        nft add rule "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" \
            ct state new tcp dport "!= @$SET_WL_PORT" \
            limit rate "${LOG_RATE_LIMIT}/second" \
            log prefix "\"$LOG_PREFIX \"" \
            accept comment "psd-log"

        log INFO "Filter rules installed"
    fi

    # Populate IP whitelist (idempotent)
    local cidr
    for cidr in "${IP_WHITELIST[@]}"; do
        nft add element "$NFT_FAMILY" "$NFT_TABLE" "$SET_WL_IP" \
            "{ $cidr }" 2>/dev/null || true
    done

    # Populate port whitelist as compact ranges
    if (( ${#PORT_WHITELIST[@]} > 0 )); then
        local ranges
        ranges=$(compact_ports_to_ranges "${!PORT_WHITELIST[@]}" | paste -sd, -)
        if [[ -n "$ranges" ]]; then
            nft add element "$NFT_FAMILY" "$NFT_TABLE" "$SET_WL_PORT" \
                "{ $ranges }" 2>/dev/null || true
        fi
    fi
}

nft_block_temp() {
    nft add element "$NFT_FAMILY" "$NFT_TABLE" "$SET_TEMP" \
        "{ $1 timeout ${TEMP_BLOCK_SECONDS}s }" 2>/dev/null || true
}

nft_block_perm() {
    nft add element "$NFT_FAMILY" "$NFT_TABLE" "$SET_PERM" \
        "{ $1 }" 2>/dev/null || true
}

nft_unblock() {
    nft delete element "$NFT_FAMILY" "$NFT_TABLE" "$SET_TEMP" "{ $1 }" 2>/dev/null || true
    nft delete element "$NFT_FAMILY" "$NFT_TABLE" "$SET_PERM" "{ $1 }" 2>/dev/null || true
}

nft_list_blocked() {
    local mode="${1:-all}"
    if [[ "$mode" == "temp" || "$mode" == "all" ]]; then
        echo "=== Temporary blocks (auto-expiring) ==="
        local out
        out=$(nft -j list set "$NFT_FAMILY" "$NFT_TABLE" "$SET_TEMP" 2>/dev/null)
        if [[ -n "$out" ]]; then
            echo "$out" | jq -r '
                .nftables[] | select(.set.elem) | .set.elem[] |
                "\(.elem.val)\t(expires in \(.elem.expires)s)"' 2>/dev/null || echo "(none)"
        else
            echo "(none)"
        fi
        echo
    fi
    if [[ "$mode" == "perm" || "$mode" == "all" ]]; then
        echo "=== Permanent blocks ==="
        local out
        out=$(nft -j list set "$NFT_FAMILY" "$NFT_TABLE" "$SET_PERM" 2>/dev/null)
        if [[ -n "$out" ]]; then
            echo "$out" | jq -r '
                .nftables[] | select(.set.elem) | .set.elem[] | .elem.val' 2>/dev/null || echo "(none)"
        else
            echo "(none)"
        fi
    fi
}

nft_count_blocked() {
    local temp perm
    temp=$(nft -j list set "$NFT_FAMILY" "$NFT_TABLE" "$SET_TEMP" 2>/dev/null | \
        jq '[.nftables[] | select(.set.elem) | .set.elem[]] | length' 2>/dev/null || echo 0)
    perm=$(nft -j list set "$NFT_FAMILY" "$NFT_TABLE" "$SET_PERM" 2>/dev/null | \
        jq '[.nftables[] | select(.set.elem) | .set.elem[]] | length' 2>/dev/null || echo 0)
    echo $(( ${temp:-0} + ${perm:-0} ))
}

# ---------------------------------------------------------------------------
# State persistence (TSV, atomic write)
# ---------------------------------------------------------------------------
load_state() {
    INCIDENTS=(); PERMANENT=(); DETECTION_HISTORY=()
    [[ ! -f "$STATE_FILE" ]] && return
    local ip inc status
    while IFS=$'\t' read -r ip inc _status; do
        [[ -z "$ip" || "$ip" == \#* ]] && continue
        INCIDENTS["$ip"]="${inc:-0}"
        [[ "$_status" == "perm" ]] && PERMANENT["$ip"]=1
    done < "$STATE_FILE"
    log INFO "State loaded: ${#INCIDENTS[@]} tracked IPs, ${#PERMANENT[@]} permanent"
}

save_state() {
    local tmp="${STATE_FILE}.tmp"
    {
        printf '#ip\tincidents\tlast_seen\tstatus\n'
        local ip status
        for ip in "${!INCIDENTS[@]}"; do
            status="temp"
            [[ -n "${PERMANENT[$ip]:-}" ]] && status="perm"
            printf '%s\t%s\t%s\t%s\n' "$ip" "${INCIDENTS[$ip]}" "$(date +%s)" "$status"
        done
    } > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$STATE_FILE"
}

restore_permanent_blocks() {
    local ip
    for ip in "${!PERMANENT[@]}"; do
        nft_block_perm "$ip"
    done
    if (( ${#PERMANENT[@]} > 0 )); then
        log INFO "Restored ${#PERMANENT[@]} permanent blocks to nftables"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------
get_log_entries() {
    local since="$1"
    journalctl -k --since "$since" --no-pager -o cat 2>/dev/null | \
        grep -F "$LOG_PREFIX" | \
        sed -nE 's/.*SRC=([0-9.]+).*DPT=([0-9]+).*/\1 \2/p'
}

analyze_connections() {
    local since="$1"
    declare -A ip_count=()
    declare -A ip_ports=()
    declare -A ip_unique=()

    local ip port
    while IFS=' ' read -r ip port; do
        [[ -z "$ip" || -z "$port" ]] && continue
        is_interesting_source "$ip" || continue
        ip_count["$ip"]=$(( ${ip_count["$ip"]:-0} + 1 ))
        ip_ports["$ip/$port"]=1
    done < <(get_log_entries "$since")

    local key
    for key in "${!ip_ports[@]}"; do
        ip="${key%/*}"
        ip_unique["$ip"]=$(( ${ip_unique["$ip"]:-0} + 1 ))
    done

    for ip in "${!ip_count[@]}"; do
        local count="${ip_count[$ip]}"
        local up="${ip_unique[$ip]:-0}"
        local -a reasons=()
        (( up >= PORT_THRESHOLD ))    && reasons+=("port-diversity=$up")
        (( count >= RATE_THRESHOLD )) && reasons+=("rate=$count")
        (( ${#reasons[@]} > 0 )) && handle_detection "$ip" "${reasons[*]}"
    done
}

check_syn_received() {
    [[ "$ENABLE_SYN_DETECTION" != "1" ]] && return 0
    local ip count
    while read -r count ip; do
        [[ -z "$ip" || -z "$count" ]] && continue
        (( count >= SYN_THRESHOLD )) || continue
        is_interesting_source "$ip" || continue
        handle_detection "$ip" "syn-received=$count"
    done < <(
        ss -tan state syn-recv 2>/dev/null | \
            awk 'NR>1 { print $5 }' | \
            sed -E 's/:[0-9]+$//' | \
            sort | uniq -c | sort -rn | \
            awk '{print $1, $2}'
    )
}

handle_detection() {
    local ip="$1" reason="$2"

    is_interesting_source "$ip" || return 0

    local now last
    now=$(date +%s)
    last="${DETECTION_HISTORY[$ip]:-0}"
    (( now - last < DETECTION_WINDOW * 2 )) && return 0
    DETECTION_HISTORY["$ip"]=$now

    [[ -n "${PERMANENT[$ip]:-}" ]] && return 0

    # Cap total rules to prevent state pollution
    local blocked
    blocked=$(nft_count_blocked)
    if (( blocked >= MAX_BLOCKED_IPS )); then
        log WARN "Max blocked IPs ($MAX_BLOCKED_IPS) reached, skipping $ip"
        return 0
    fi

    local inc="${INCIDENTS[$ip]:-0}"

    if (( inc == 0 )); then
        nft_block_temp "$ip"
        INCIDENTS["$ip"]=1
        log ALERT "TEMPORARY BLOCK $ip | reason: $reason | duration: ${TEMP_BLOCK_SECONDS}s"
    else
        nft_block_perm "$ip"
        PERMANENT["$ip"]=1
        INCIDENTS["$ip"]=$(( inc + 1 ))
        log ALERT "PERMANENT BLOCK $ip | reason: $reason | prior incidents: $inc"
    fi

    save_state
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
main_loop() {
    local since="${DETECTION_WINDOW} seconds ago"
    while $RUNNING; do
        sleep "$POLL_INTERVAL"
        $RUNNING || break
        analyze_connections "$since" || log ERROR "analyze_connections failed"
        check_syn_received       || log ERROR "check_syn_received failed"
    done
}

# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------
cleanup() {
    log INFO "Shutdown requested"
    RUNNING=false
    save_state 2>/dev/null || true
    # NOTE: nftables rules/blocks are deliberately NOT removed
    # so existing blocks remain active across restarts.
    exit 0
}

reload_config() {
    log INFO "SIGHUP: reloading config and whitelist"
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    load_port_whitelist
    nft_setup
}

# ---------------------------------------------------------------------------
# CLI subcommands
# ---------------------------------------------------------------------------
show_help() {
    cat <<EOF
Usage: $0 [command]

Commands:
  (none)         Run daemon in foreground (usually via systemd)
  --status       Show current status and statistics
  --list         List all blocked IPs
  --list-temp    List temporary blocks only
  --list-perm    List permanent blocks only
  --unblock IP   Remove IP from block lists and state
  --help         Show this help
EOF
}

do_status() {
    local temp perm
    temp=$(nft -j list set "$NFT_FAMILY" "$NFT_TABLE" "$SET_TEMP" 2>/dev/null | \
        jq '[.nftables[] | select(.set.elem) | .set.elem[]] | length' 2>/dev/null || echo 0)
    perm=$(nft -j list set "$NFT_FAMILY" "$NFT_TABLE" "$SET_PERM" 2>/dev/null | \
        jq '[.nftables[] | select(.set.elem) | .set.elem[]] | length' 2>/dev/null || echo 0)

    cat <<EOF
=== PortScan Defender Status ===
Detection window:      ${DETECTION_WINDOW}s
Port threshold:        ${PORT_THRESHOLD}
Rate threshold:        ${RATE_THRESHOLD}
SYN threshold:         ${SYN_THRESHOLD}
Temp block duration:   ${TEMP_BLOCK_SECONDS}s
Max blocked IPs:       ${MAX_BLOCKED_IPS}
Tracked IPs:           ${#INCIDENTS[@]}
Temporary blocks:      ${temp:-0}
Permanent blocks:      ${perm:-0}
Whitelisted ports:     ${#PORT_WHITELIST[@]}
nftables table:        $NFT_FAMILY $NFT_TABLE
EOF
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
main() {
    log_setup

    case "${1:-}" in
        --help|-h)  show_help; exit 0 ;;
        --list)     load_state; nft_list_blocked all; exit 0 ;;
        --list-temp) load_state; nft_list_blocked temp; exit 0 ;;
        --list-perm) load_state; nft_list_blocked perm; exit 0 ;;
        --unblock)
            [[ -z "${2:-}" ]] && { echo "IP required" >&2; exit 1; }
            is_valid_ipv4 "$2" || { echo "Invalid IPv4: $2" >&2; exit 1; }
            load_state
            nft_unblock "$2"
            unset "INCIDENTS[$2]" "PERMANENT[$2]" 2>/dev/null || true
            save_state
            log WARN "Manually unblocked $2"
            echo "Unblocked: $2"
            exit 0
            ;;
        --status)
            load_port_whitelist
            load_state
            do_status
            exit 0
            ;;
        "")  : ;;  # daemon mode
        *)   echo "Unknown command: $1" >&2; show_help >&2; exit 1 ;;
    esac

    # --- daemon mode requirements ---
    if (( EUID != 0 )); then
        log ERROR "Must run as root"
        exit 1
    fi

    local tool
    for tool in nft journalctl jq ss awk sed; do
        command -v "$tool" >/dev/null || {
            log ERROR "Required tool missing: $tool"
            exit 1
        }
    done

    log INFO "==========================================="
    log INFO "PortScan Defender starting (PID $$)"
    log INFO "==========================================="

    load_port_whitelist
    load_state
    nft_setup
    restore_permanent_blocks

    trap cleanup       SIGTERM SIGINT SIGQUIT
    trap reload_config SIGHUP

    log INFO "Daemon ready. Poll interval: ${POLL_INTERVAL}s."

    main_loop
}

main "$@"