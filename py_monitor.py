#!/usr/bin/env python3
#
# name.........: resource_monitor
# description..: Resource monitor
# author.......: Alan da Silva Alves
# version......: 5.0.0
# date.........: 7/28/2025
# github.......: github.com/treinalinux
# updates......: 5.0.0 - multipath
#                4.0.0 - Coverages
#                3.0.0 - Sensors
#
# ---------------------------------------------------------------------------
# CABEÇALHO
# ---------------------------------------------------------------------------
"""
Monitor de Recursos e Troubleshooting - RHEL 8+ / HPC / BeeGFS
[COVERAGE: Gargalos] - CPU (I/O Wait %), RAM, Swap, Discos, Redes e Sensores.
[COVERAGE: Top Processos] - Leitura otimizada via os.listdir (Zero-Overhead).
[COVERAGE: Throughput/Latency] - Latência I/O milimétrica por LUN/Mount.
[COVERAGE: Multipath SAN] - Árvore de Topologia (Com filtro inteligente de LVM).
[COVERAGE: Auditoria Causa-Raiz] - Delta SAS PHY, RDMA, MTU Mismatch e Buffers.
"""

# ---------------------------------------------------------------------------
# IMPORTAÇÕES
# ---------------------------------------------------------------------------
import argparse
import os
import time
import csv
import collections
import glob
from datetime import datetime
from typing import Dict, Tuple, List, Optional

# ---------------------------------------------------------------------------
# CONSTANTES E CACHES
# ---------------------------------------------------------------------------
SECTOR_SIZE = 512
TERMINAL_WIDTH = 118
LEFT_COL_WIDTH = 44

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"

_PACEMAKER_CACHE = {"time": 0.0, "status": ("ONLINE", "OK", "Desconhecido")}
_SENSORS_CACHE = {"time": 0.0, "data": []}


# ---------------------------------------------------------------------------
# FUNÇÕES DE UTILIDADE
# ---------------------------------------------------------------------------
def get_raw_hostname() -> str:
    try:
        return os.uname().nodename.split('.')[0]
    except Exception:
        return "localhost"


def get_hostname() -> str:
    return get_raw_hostname().upper()


def format_size(bytes_val: float, is_rate: bool = False) -> str:
    if bytes_val is None:
        return "0.0 B/s" if is_rate else "0.0 B"
        
    suffix = "/s" if is_rate else ""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}{suffix}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} EB{suffix}"


def render_sparkline(data: List[float], width: int = 15, absolute_max: float = None) -> str:
    if not data:
        return " " * width
        
    data = data[-width:]
    if len(data) < width:
        data = [0.0] * (width - len(data)) + data
        
    chars = " ▂▃▄▅▆▇█"
    min_val = 0.0 if absolute_max is not None else min(data)
    max_val = absolute_max if absolute_max is not None else max(data)
    range_val = max_val - min_val if max_val > min_val else 1.0
    
    sparkline = ""
    for val in data:
        val = max(min_val, min(max_val, val))
        idx = int(((val - min_val) / range_val) * (len(chars) - 1))
        sparkline += chars[idx]
        
    return sparkline


def render_progress_bar(percentage: float, max_width: int = 30, show_suffix: bool = True) -> str:
    if percentage >= 95.0:
        color, alert_suffix = RED, " [CRIT]"
    elif percentage >= 80.0:
        color, alert_suffix = YELLOW, " [WARN]"
    else:
        color, alert_suffix = GREEN, ""
        
    if not show_suffix:
        alert_suffix = ""
        
    filled = int((percentage / 100) * max_width)
    bar = f"{color}{'█' * filled}{'░' * (max_width - filled)}{RESET}"
    return f"{bar} {percentage:5.1f}%{color}{alert_suffix}{RESET}"


def print_separator(char: str = "─") -> None:
    print(f"{CYAN}{char * TERMINAL_WIDTH}{RESET}")


def calc_device_io(dev_name: str, curr_disk: Dict, prev_disk: Dict, interval: float) -> Tuple[float, float, float]:
    if dev_name in curr_disk and dev_name in prev_disk:
        c = curr_disk[dev_name]
        p = prev_disk[dev_name]
        r_bps = (c[0] - p[0]) / interval
        w_bps = (c[1] - p[1]) / interval
        iops = ((c[2] - p[2]) + (c[3] - p[3])) / interval
        return max(0.0, r_bps), max(0.0, w_bps), max(0.0, iops)
    return 0.0, 0.0, 0.0


# ---------------------------------------------------------------------------
# MOTORES DE AUDITORIA DE HARDWARE (DMESG, SAS, IB)
# ---------------------------------------------------------------------------
def get_kernel_audit(dmesg_start_lines: int) -> Tuple[List[str], List[str]]:
    recent_logs = []
    historical_logs = []
    
    kw_recent = [
        'i/o error', 'scsi error', 'link down', 'degraded', 'multipath', 
        'out of memory', 'throttled', 'timeout', 'abort', 'resetting', 
        'hardware error', 'fault', 'dropped', 'powervault', 'me5024', 
        'mpt3sas', 'mlx5', 'symbol error', 'sas error'
    ]
    
    kw_history = [
        'negotiated', 'downgrade', 'degraded', 'link down', 
        'multipath: failing path', 'sas error', 'mpt3sas_cm0: port enable', 
        'link up at'
    ]
    
    try:
        stream = os.popen('dmesg -T 2>/dev/null')
        all_lines = stream.read().splitlines()
        stream.close()
        
        if len(all_lines) > dmesg_start_lines:
            past_lines = all_lines[max(0, dmesg_start_lines - 5000):dmesg_start_lines]
            current_lines = all_lines[dmesg_start_lines:]
        else:
            past_lines = all_lines[-5000:]
            current_lines = []
            
        for line in current_lines:
            if any(kw in line.lower() for kw in kw_recent):
                recent_logs.append(line.strip())
                
        for line in past_lines:
            if any(kw in line.lower() for kw in kw_history):
                historical_logs.append(line.strip())
                
    except Exception:
        pass
        
    return recent_logs[-5:], historical_logs[-5:]


def get_sas_phy_stats() -> Dict[str, Dict]:
    stats = {}
    phy_path = "/sys/class/sas_phy"
    if os.path.exists(phy_path):
        try:
            for phy in os.listdir(phy_path):
                base = os.path.join(phy_path, phy)
                if not os.path.isdir(base):
                    continue
                    
                err_count = 0
                err_files = [
                    'invalid_dword_count', 'running_disparity_error_count', 
                    'loss_of_dword_sync_count', 'phy_reset_problem_count'
                ]
                
                for e_file in err_files:
                    try:
                        with open(os.path.join(base, e_file), "r") as f:
                            err_count += int(f.read().strip())
                    except Exception:
                        pass
                        
                max_rate, neg_rate, degraded = "", "", False
                try:
                    with open(os.path.join(base, "maximum_linkrate"), "r") as f:
                        max_rate = f.read().strip()
                    with open(os.path.join(base, "negotiated_linkrate"), "r") as f:
                        neg_rate = f.read().strip()
                        
                    if "Unknown" not in neg_rate and "Unknown" not in max_rate and neg_rate != max_rate:
                        if float(neg_rate.split()[0]) < float(max_rate.split()[0]):
                            degraded = True
                except Exception:
                    pass
                    
                stats[phy] = {
                    'errors': err_count, 
                    'max_rate': max_rate, 
                    'neg_rate': neg_rate, 
                    'degraded': degraded
                }
        except Exception:
            pass
    return stats


def get_sas_phy_alerts(baseline: Dict[str, Dict], current: Dict[str, Dict]) -> List[str]:
    alerts = []
    for phy, curr_data in current.items():
        prev_data = baseline.get(phy, {'errors': 0})
        
        if curr_data['degraded']:
            msg = f"[HBA/SAS] Downgrade Lógico ({phy}): Operando a {curr_data['neg_rate']} (Suporta {curr_data['max_rate']})"
            alerts.append(msg)
            
        delta_err = curr_data['errors'] - prev_data['errors']
        if delta_err > 0:
            msg = f"[HBA/SAS] FALHA FÍSICA ATIVA ({phy}): {delta_err} NOVOS erros gerados na sessão!"
            alerts.append(msg)
            
    return alerts


def get_ib_stats(ib_devices: Optional[List[str]]) -> Dict[str, Dict]:
    stats = {}
    if not ib_devices:
        return stats
        
    for ib_dev in ib_devices:
        base_path = f"/sys/class/infiniband/{ib_dev}/ports/1"
        if not os.path.exists(base_path):
            continue

        rx_bytes, tx_bytes = 0.0, 0.0
        try:
            with open(f"{base_path}/counters/port_rcv_data", "r") as f:
                rx_bytes = int(f.read().strip()) * 4
            with open(f"{base_path}/counters/port_xmit_data", "r") as f:
                tx_bytes = int(f.read().strip()) * 4
        except Exception:
            pass

        errs = {'symbol_error': 0, 'link_downed': 0, 'port_xmit_discards': 0}
        for err_file in errs.keys():
            try:
                with open(f"{base_path}/counters/{err_file}", "r") as f:
                    errs[err_file] = int(f.read().strip())
            except Exception:
                pass

        state = "UNKNOWN"
        try:
            with open(f"{base_path}/state", "r") as f:
                state = f.read().strip()
        except Exception:
            pass

        stats[ib_dev] = {
            'rx_bytes': rx_bytes, 
            'tx_bytes': tx_bytes, 
            'errors': errs, 
            'state': state
        }
        
    return stats


def get_ib_alerts(baseline: Dict[str, Dict], current: Dict[str, Dict]) -> List[str]:
    alerts = []
    for ib, curr_data in current.items():
        prev_data = baseline.get(ib, {})
        if not prev_data:
            continue

        if curr_data['state'] != prev_data.get('state', '') and 'ACTIVE' not in curr_data['state']:
            alerts.append(f"[RDMA/IB] PORTA INATIVA ({ib}): Link mudou para o estado {curr_data['state']}")

        errs_curr = curr_data.get('errors', {})
        errs_base = prev_data.get('errors', {})

        sym_err = errs_curr.get('symbol_error', 0) - errs_base.get('symbol_error', 0)
        if sym_err > 0:
            alerts.append(f"[RDMA/IB] FALHA DE CABO/ÓPTICA ({ib}): {sym_err} novos Symbol Errors")

        disc_err = errs_curr.get('port_xmit_discards', 0) - errs_base.get('port_xmit_discards', 0)
        if disc_err > 0:
            alerts.append(f"[RDMA/IB] CONGESTIONAMENTO DE MALHA ({ib}): {disc_err} descartes de transmissão")

        link_down = errs_curr.get('link_downed', 0) - errs_base.get('link_downed', 0)
        if link_down > 0:
            alerts.append(f"[RDMA/IB] FLAPPING DETECTADO ({ib}): O link caiu {link_down} vezes!")
            
    return alerts


def get_multipath_topology() -> Dict[str, Dict]:
    topology = {}
    try:
        for dm in os.listdir('/sys/block'):
            if dm.startswith('dm-'):
                try:
                    with open(f"/sys/block/{dm}/dm/uuid", "r") as f:
                        dm_uuid = f.read().strip()
                        
                    # Filtra apenas Device Mappers que sejam Multipath SAN reais
                    if not dm_uuid.startswith('mpath-'):
                        continue 
                        
                    with open(f"/sys/block/{dm}/dm/name", "r") as f:
                        name = f.read().strip()
                        
                    slaves = os.listdir(f"/sys/block/{dm}/slaves")
                    if slaves:
                        topology[dm] = {"name": name, "slaves": slaves}
                        
                except Exception:
                    pass
    except Exception:
        pass
    return topology


# ---------------------------------------------------------------------------
# COLETA DE DADOS GERAIS (SISTEMA E REDE PROFUNDA)
# ---------------------------------------------------------------------------
def get_system_data(
    target_disks: Optional[List[str]] = None, 
    target_mounts: Optional[List[str]] = None, 
    target_net: Optional[List[str]] = None
) -> Tuple[Dict, str, Tuple[float, float, float, float], Dict, Dict, Dict]:
    
    cpu_cores_data = {}
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                if parts[0].startswith('cpu') and parts[0] != 'cpu':
                    values = [int(x) for x in parts[1:]]
                    active = sum(values[:3]) + sum(values[5:8])
                    idle = values[3]
                    iowait = values[4] if len(values) > 4 else 0
                    cpu_cores_data[parts[0]] = (active, idle, iowait)
    except FileNotFoundError:
        pass

    load_avg_str = "0.00 0.00 0.00"
    try:
        with open('/proc/loadavg', 'r') as f:
            load_avg_str = " ".join(f.read().split()[:3])
    except Exception:
        pass

    mem_total, mem_available, swap_total, swap_free = 0, 0, 0, 0
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                if 'MemTotal:' in line:
                    mem_total = int(parts[1])
                elif 'MemAvailable:' in line:
                    mem_available = int(parts[1])
                elif 'SwapTotal:' in line:
                    swap_total = int(parts[1])
                elif 'SwapFree:' in line:
                    swap_free = int(parts[1])
    except FileNotFoundError:
        pass
        
    memory_usage = ((mem_total - mem_available) / mem_total) * 100 if mem_total > 0 else 0.0
    swap_usage = ((swap_total - swap_free) / swap_total) * 100 if swap_total > 0 else 0.0

    disk_data = {}
    try:
        with open('/proc/diskstats', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 13 and parts[2].startswith(('sd', 'nvme', 'dm-')):
                    disk_data[parts[2]] = (
                        int(parts[5]) * SECTOR_SIZE, int(parts[9]) * SECTOR_SIZE, 
                        int(parts[3]), int(parts[7]), int(parts[6]), 
                        int(parts[10]), int(parts[12])
                    )
    except FileNotFoundError:
        pass

    mount_data = {}
    if target_mounts:
        for mount in target_mounts:
            if not os.path.exists(mount):
                continue
                
            usage, total_bytes = 0.0, 0.0
            r_bytes, w_bytes, r_iops, w_iops, t_read, t_write, t_io = (None,) * 7
            
            try:
                st = os.statvfs(mount)
                st_total_bytes = st.f_blocks * st.f_frsize
                if st_total_bytes > 0:
                    usage = ((st_total_bytes - (st.f_bavail * st.f_frsize)) / st_total_bytes) * 100
                    total_bytes = float(st_total_bytes)
            except OSError:
                pass
                
            try:
                st_dev = os.stat(mount).st_dev
                major, minor = os.major(st_dev), os.minor(st_dev)
                with open('/proc/diskstats', 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 13 and int(parts[0]) == major and int(parts[1]) == minor:
                            r_bytes = int(parts[5]) * SECTOR_SIZE
                            w_bytes = int(parts[9]) * SECTOR_SIZE
                            r_iops = int(parts[3])
                            w_iops = int(parts[7])
                            t_read = int(parts[6])
                            t_write = int(parts[10])
                            t_io = int(parts[12])
                            break
            except Exception:
                pass
                
            mount_data[mount] = (usage, total_bytes, (r_bytes, w_bytes, r_iops, w_iops, t_read, t_write, t_io))

    net_data = {}
    if target_net:
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' not in line:
                        continue
                    iface_name, stats = line.split(':')
                    iface_name = iface_name.strip()
                    
                    if iface_name in target_net:
                        parts = stats.split()
                        mtu = 1500
                        try:
                            with open(f"/sys/class/net/{iface_name}/mtu", "r") as fm:
                                mtu = int(fm.read().strip())
                        except Exception:
                            pass
                            
                        net_data[iface_name] = (
                            int(parts[0]), int(parts[8]), 
                            int(parts[3]), int(parts[11]),
                            int(parts[2]), int(parts[10]),
                            int(parts[4]), int(parts[12]),
                            mtu
                        )
        except FileNotFoundError:
            pass

    return cpu_cores_data, load_avg_str, (memory_usage, mem_total * 1024.0, swap_usage, swap_total * 1024.0), disk_data, mount_data, net_data


def get_top_processes(prev_procs: Dict, interval: float) -> Tuple[Dict, List, List, List, List]:
    curr_procs = {}
    try:
        clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        page_size = os.sysconf('SC_PAGE_SIZE')
    except Exception:
        clk_tck = 100
        page_size = 4096
        
    process_list = []
    
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
            
        pid_dir = f"/proc/{pid}"
        try:
            with open(f"{pid_dir}/stat", 'r') as f:
                stat_content = f.read()
                comm_start = stat_content.find('(') + 1
                comm_end = stat_content.rfind(')')
                comm = stat_content[comm_start:comm_end]
                
                rest = stat_content[comm_end+2:].split()
                total_time = int(rest[11]) + int(rest[12])
                
            with open(f"{pid_dir}/statm", 'r') as f:
                rss_bytes = int(f.read().split()[1]) * page_size
                
            r_bytes, w_bytes = 0, 0
            try:
                with open(f"{pid_dir}/io", 'r') as f:
                    for line in f:
                        if line.startswith('read_bytes:'):
                            r_bytes = int(line.split()[1])
                        elif line.startswith('write_bytes:'):
                            w_bytes = int(line.split()[1])
            except Exception:
                pass 
            
            curr_procs[pid] = {
                'comm': comm, 
                'cpu_ticks': total_time, 
                'r_bytes': r_bytes, 
                'w_bytes': w_bytes
            }
            
            cpu_usage, r_rate, w_rate = 0.0, 0.0, 0.0
            if pid in prev_procs:
                prev = prev_procs[pid]
                dt = total_time - prev['cpu_ticks']
                if dt > 0:
                    cpu_usage = (dt / clk_tck) / interval * 100.0
                r_rate = max(0.0, (r_bytes - prev['r_bytes']) / interval)
                w_rate = max(0.0, (w_bytes - prev['w_bytes']) / interval)
                
            process_list.append({
                'pid': pid, 'comm': comm, 'cpu': cpu_usage, 
                'mem': rss_bytes, 'read': r_rate, 'write': w_rate
            })
        except Exception:
            continue

    top_cpu = sorted(process_list, key=lambda x: x['cpu'], reverse=True)[:3]
    top_mem = sorted(process_list, key=lambda x: x['mem'], reverse=True)[:3]
    top_read = sorted(process_list, key=lambda x: x['read'], reverse=True)[:3]
    top_write = sorted(process_list, key=lambda x: x['write'], reverse=True)[:3]
    
    return curr_procs, top_cpu, top_mem, top_read, top_write


# ---------------------------------------------------------------------------
# SENSORES, IDRAC E PACEMAKER
# ---------------------------------------------------------------------------
def get_sensor_thresholds(sensor_name: str) -> Tuple[float, float]:
    name = sensor_name.lower()
    if "cpu" in name or "pkg" in name or "core" in name or "gpu" in name:
        return 80.0, 90.0
    if "nvme" in name:
        return 65.0, 75.0
    if "sata" in name or "hdd" in name or "disk" in name:
        return 45.0, 55.0
    return 60.0, 70.0


def get_hardware_sensors_cached(cache_interval: float, use_idrac_log: bool, idrac_types: List[str]) -> List[Tuple[str, str, int]]:
    global _SENSORS_CACHE
    now = time.time()
    if now - _SENSORS_CACHE["time"] < cache_interval:
        return _SENSORS_CACHE["data"]
        
    sensors = []
    
    if use_idrac_log:
        raw_host = get_raw_hostname()
        log_paths = [
            f"/var/log/compliance/{raw_host}.html", 
            f"/var/log/compliance/{raw_host.lower()}.html", 
            f"/var/log/compliance/{os.uname().nodename}.html"
        ]
        
        file_content = ""
        for path in log_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_content = f.read()
                    break
                except Exception:
                    pass
                    
        if file_content:
            current_type = "UNK"
            allowed_types = [t.upper() for t in idrac_types]
            
            for line in file_content.splitlines():
                line = line.strip()
                if not line or line.startswith('---') or line.startswith('<Sensor') or line.startswith('[Key'):
                    continue
                if line.startswith('Sensor Type :'):
                    current_type = line.split(':')[-1].strip().upper()
                    continue
                if current_type not in allowed_types:
                    continue
                    
                words = line.split()
                status_idx, status_val = -1, ""
                for i, w in enumerate(words):
                    if w.lower() in {'ok', 'present', 'good', 'critical', 'warning', 'fail', 'error', 'non-critical', 'non-recoverable'}:
                        status_idx, status_val = i, w.lower()
                        break
                        
                if status_idx > 0:
                    raw_name = " ".join(words[:status_idx])
                    data_words = words[status_idx+1:]
                    val_str = status_val.capitalize() 
                    
                    if data_words:
                        if current_type == "POWER":
                            val_str = data_words[-1]
                            for dw in data_words:
                                if 'watt' in dw.lower():
                                    val_str = dw
                                    break
                        else:
                            val_str = data_words[0]
                            
                    level = 2 if status_val in ['critical', 'fail', 'error', 'non-recoverable'] else (1 if status_val in ['warning', 'non-critical'] else 0)
                    type_map = {"POWER": "PWR", "TEMPERATURE": "TMP", "FAN": "FAN", "VOLTAGE": "VLT", "PROCESSOR": "CPU", "MEMORY": "MEM", "MAX DIMM TEMPERATURE": "TMP"}
                    sensors.append((f"[{type_map.get(current_type, current_type[:3])}] {raw_name}", val_str, level))
    else:
        for zone in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
            try:
                with open(os.path.join(zone, "type"), "r") as f:
                    s_type = f.read().strip()
                with open(os.path.join(zone, "temp"), "r") as f:
                    c_temp = float(f.read().strip()) / 1000.0
                    
                if c_temp > 0:
                    friendly = "CPU/Pkg" if s_type == "x86_pkg_temp" else "Motherboard" if s_type == "acpitz" else f"Zone ({s_type})"
                    w, c = get_sensor_thresholds(friendly)
                    sensors.append((f"[SYS] {friendly}", f"{c_temp:.1f}°C", 2 if c_temp >= c else (1 if c_temp >= w else 0)))
            except Exception:
                continue

        for h_dir in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
            try:
                with open(os.path.join(h_dir, "name"), "r") as f:
                    d_name = f.read().strip()
                    
                if d_name in ["coretemp", "acpitz"]:
                    continue
                    
                for t_in in sorted(glob.glob(os.path.join(h_dir, "temp*_input"))):
                    lbl_p = os.path.join(h_dir, f"{os.path.basename(t_in).split('_')[0]}_label")
                    lbl = f" ({open(lbl_p).read().strip()})" if os.path.exists(lbl_p) else ""
                    c_temp = float(open(t_in).read().strip()) / 1000.0
                    
                    if c_temp > 0:
                        w, c = get_sensor_thresholds(f"[HW] {d_name}{lbl}")
                        sensors.append((f"[HW] {d_name}{lbl}", f"{c_temp:.1f}°C", 2 if c_temp >= c else (1 if c_temp >= w else 0)))
            except Exception:
                continue

        for dev in sorted([os.path.basename(d) for d in glob.glob("/dev/sd[a-z]") + glob.glob("/dev/nvme[0-9]*n[0-9]")]):
            try:
                out = os.popen(f"sudo smartctl -A /dev/{dev} 2>/dev/null").read()
                det_t = None
                for line in out.splitlines():
                    if "temperature_celsius" in line.lower() or ("temperature:" in line.lower() and "celsius" in line.lower()):
                        cols = line.split()
                        if "temperature_celsius" in line.lower() and len(cols) >= 10:
                            det_t = float(cols[9])
                        elif len(cols) >= 2:
                            det_t = float(cols[1])
                        break
                        
                if det_t:
                    w, c = get_sensor_thresholds(f"[DSK] {dev}")
                    dtype_name = "NVMe" if "nvme" in dev else "SATA"
                    sensors.append((f"[DSK] {dev} {dtype_name}", f"{det_t:.1f}°C", 2 if det_t >= c else (1 if det_t >= w else 0)))
            except Exception:
                continue

        try:
            n_out = os.popen("nvidia-smi --query-gpu=index,name,temperature.gpu --format=csv,noheader,nounits 2>/dev/null").read().strip()
            if n_out:
                for line in n_out.splitlines():
                    cols = [c.strip() for c in line.split(",")]
                    if len(cols) == 3: 
                        temp = float(cols[2])
                        w, c = get_sensor_thresholds(f"[GPU] {cols[0]} {cols[1]}")
                        sensors.append((f"[GPU] {cols[0]} {cols[1]}", f"{temp:.1f}°C", 2 if temp >= c else (1 if temp >= w else 0)))
        except Exception:
            pass

    _SENSORS_CACHE["time"] = now
    _SENSORS_CACHE["data"] = sensors
    return sensors


def get_pacemaker_status_cached() -> Tuple[str, str, str]:
    global _PACEMAKER_CACHE
    now = time.time()
    
    if now - _PACEMAKER_CACHE["time"] < 5.0:
        return _PACEMAKER_CACHE["status"]
        
    status_text, quorum_text, node_text, success = "ONLINE", "OK", get_hostname(), False
    
    for cmd in ['crm_mon -s -1', '/usr/sbin/crm_mon -s -1', 'pcs status cluster']:
        try:
            stream = os.popen(cmd)
            output = stream.read()
            exit_code = stream.close()
            
            if exit_code is None or exit_code == 0:
                success = True
                out_upper = output.upper()
                if "NO QUORUM" in out_upper or "OFFLINE" in out_upper or "WARNING" in out_upper:
                    quorum_text = "SEM QUORUM" if "NO QUORUM" in out_upper else "OK"
                    status_text = "WARN"
                break
        except Exception:
            continue
            
    if not success:
        try:
            if os.popen('pgrep -x pacemakerd').read().strip():
                status_text, quorum_text = "ONLINE (Daemon)", "OK"
            else:
                status_text, quorum_text = "STANDALONE", "N/A"
        except Exception:
            status_text, quorum_text = "STANDALONE", "N/A"
            
    _PACEMAKER_CACHE["time"] = now
    _PACEMAKER_CACHE["status"] = (status_text, quorum_text, node_text)
    return _PACEMAKER_CACHE["status"]


def get_physical_mounts(all_mounts: bool = False) -> List[str]:
    excluded_fs = {
        'tmpfs', 'devtmpfs', 'proc', 'sysfs', 'securityfs', 'cgroup', 'cgroup2', 
        'pstore', 'bpf', 'autofs', 'mqueue', 'hugetlbfs', 'debugfs', 'tracefs', 
        'configfs', 'fuse', 'fusectl', 'squashfs', 'overlay', 'rpc_pipefs', 
        'efivarfs', 'devpts', 'ramfs', 'nsfs', 'nfs', 'nfs4', 'cifs', 'smb3'
    }
    excluded_prefixes = (
        '/run/', '/sys/', '/dev/', '/proc/', '/snap/', 
        '/var/lib/docker/', '/var/lib/containers/'
    )
    os_mounts = {'/', '/boot', '/boot/efi', '/var', '/var/log', '/home', '/tmp', '/usr', '/etc'}
    mounts = []
    
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    dev = parts[0]
                    mt = parts[1].replace('\\040', ' ')
                    fs = parts[2]
                    
                    if fs in excluded_fs or dev.startswith('/dev/loop') or mt.startswith(excluded_prefixes) or 'netns' in mt:
                        continue
                    if not all_mounts and mt in os_mounts:
                        continue
                        
                    mounts.append(mt)
    except FileNotFoundError:
        pass
        
    mounts = list(dict.fromkeys(mounts))
    if '/' in mounts:
        mounts.remove('/')
        mounts.insert(0, '/')
    return mounts


# ---------------------------------------------------------------------------
# EXPORTAÇÃO CSV E RELATÓRIO FINAL CAUSA-RAIZ
# ---------------------------------------------------------------------------
def export_to_csv(
    filename: str, hist_time: List[str], hist_cpu: List[Dict], 
    hist_mem: List[float], hist_mounts: List[Dict], hist_procs: List[Dict], 
    hist_sas: List[Dict], hist_ib: List[Dict]
):
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "CPU_Geral_Pct", "RAM_Pct", "Diretorio_LUN", 
                "Uso_FS_Pct", "Leitura_MBps", "Escrita_MBps", "IOPS_Total", 
                "Latencia_ms", "Utilizacao_Pct", "Top_CPU_Proc", "Top_RAM_Proc", 
                "Top_Read_Proc", "Top_Write_Proc", "SAS_Erros", "SAS_Degradados", 
                "IB_SymErros", "IB_Discards"
            ])
            
            for i in range(len(hist_time)):
                mt_written = False
                cpu_geral = sum(hist_cpu[i].values()) / len(hist_cpu[i]) if hist_cpu[i] else 0.0
                
                c_p = hist_procs[i]['cpu'] if i < len(hist_procs) else "-"
                m_p = hist_procs[i]['mem'] if i < len(hist_procs) else "-"
                r_p = hist_procs[i]['read'] if i < len(hist_procs) else "-"
                w_p = hist_procs[i]['write'] if i < len(hist_procs) else "-"
                
                s_errs = hist_sas[i]['delta_errs'] if i < len(hist_sas) else 0
                s_degs = hist_sas[i]['degraded'] if i < len(hist_sas) else 0
                
                ib_errs = hist_ib[i]['sym_errs'] if i < len(hist_ib) else 0
                ib_discs = hist_ib[i]['discards'] if i < len(hist_ib) else 0
                
                if hist_mounts and hist_mounts[i]:
                    for mt, data in hist_mounts[i].items():
                        r_mbps = data['r_bps'] / (1024 * 1024)
                        w_mbps = data['w_bps'] / (1024 * 1024)
                        
                        writer.writerow([
                            hist_time[i], f"{cpu_geral:.1f}", f"{hist_mem[i]:.1f}", 
                            mt, f"{data['usage']:.1f}", f"{r_mbps:.3f}", 
                            f"{w_mbps:.3f}", f"{data['iops']:.1f}", 
                            f"{data['lat']:.2f}", f"{data['util']:.1f}", 
                            c_p, m_p, r_p, w_p, s_errs, s_degs, ib_errs, ib_discs
                        ])
                        mt_written = True
                        
                if not mt_written:
                    writer.writerow([
                        hist_time[i], f"{cpu_geral:.1f}", f"{hist_mem[i]:.1f}", 
                        "-", "-", "-", "-", "-", "-", "-", 
                        c_p, m_p, r_p, w_p, s_errs, s_degs, ib_errs, ib_discs
                    ])
                    
        print(f"[{GREEN}✓{RESET}] Histórico exportado com sucesso para: {BOLD}{filename}{RESET}")
    except Exception as e:
        print(f"[{RED}ERRO{RESET}] Falha ao exportar CSV: {e}")


def display_summary_report(
    cpu_history: List[Dict[str, float]], mem_history: List[float], 
    mount_history: List[Dict[str, Dict]], mem_total_bytes: float, 
    mount_totals: Dict[str, float], hist_procs: List[Dict], 
    env_type: str, dmesg_start_lines: int, sas_baseline: Dict, 
    curr_sas: Dict, ib_baseline: Dict, curr_ib: Dict, 
    hist_net_stats: Dict[str, Dict]
) -> None:
    
    if not cpu_history or not mem_history:
        return
        
    print("\n")
    print(f"{CYAN}╭{'─' * (TERMINAL_WIDTH - 2)}╮{RESET}")
    print(f"{CYAN}│{RESET} {BOLD}{'RELATÓRIO DE MÉDIAS DO PERÍODO E TROUBLESHOOTING CAUSA-RAIZ'.center(TERMINAL_WIDTH - 4)}{RESET} {CYAN}│{RESET}")
    print(f"{CYAN}╰{'─' * (TERMINAL_WIDTH - 2)}╯{RESET}")
    
    all_cores = sorted(cpu_history[0].keys(), key=lambda x: int(x[3:]))
    global_cpu_hist = [sum(s.values()) / len(s) if s else 0.0 for s in cpu_history]
    
    print(f"{BOLD} Média de Carga por Núcleo (CPU):{RESET}")
    cols = 4 if len(all_cores) > 16 else 2
    rows = (len(all_cores) + cols - 1) // cols
    cores_cols = [[] for _ in range(cols)]
    
    for idx, core in enumerate(all_cores):
        avg_c = sum(s[core] for s in cpu_history) / len(cpu_history)
        cores_cols[idx // rows].append(f"   ├─ {core:<6}: {avg_c:5.1f}%")
        
    for r in range(rows):
        row_parts = []
        for c in range(cols):
            if r < len(cores_cols[c]):
                row_parts.append(cores_cols[c][r])
            else:
                row_parts.append("")
                
        if cols == 4:
            print("".join(f"{p:<28}" for p in row_parts))
        else:
            print("".join(f"{p:<50}" for p in row_parts))
        
    print_separator("─")
    avg_global_cpu = sum(global_cpu_hist) / len(global_cpu_hist) if global_cpu_hist else 0.0
    spark_cpu = render_sparkline(global_cpu_hist, width=30, absolute_max=100.0)
    print(f" {BOLD}{'Média Geral CPU:':<33}{RESET} {avg_global_cpu:>5.1f}%   │{CYAN}{spark_cpu}{RESET}│")
    
    avg_mem = sum(mem_history) / len(mem_history)
    spark_mem = render_sparkline(mem_history, width=30, absolute_max=100.0)
    print(f" {BOLD}{f'Média Geral RAM [{format_size(mem_total_bytes)}]:':<33}{RESET} {avg_mem:>5.1f}%   │{CYAN}{spark_mem}{RESET}│")
    
    if hist_procs:
        print_separator("─")
        print(f" {BOLD}MAIORES OFENSORES E CONSUMIDORES DE RECURSO DO PERÍODO{RESET}")
        
        def get_most_common(key):
            valid = [p[key] for p in hist_procs if p[key] != "-"]
            if not valid:
                return "Nenhum pico agressivo registrado"
            most_common, count = collections.Counter(valid).most_common(1)[0]
            pct = (count / len(hist_procs)) * 100
            return f"{most_common} (Liderou em {count} de {len(hist_procs)} amostras - {pct:.1f}%)"
            
        print(f"   🔥 {'CPU':<10} : {get_most_common('cpu')}")
        print(f"   🧠 {'RAM':<10} : {get_most_common('mem')}")
        print(f"   📖 {'Leitura':<10} : {get_most_common('read')}")
        print(f"   💾 {'Escrita':<10} : {get_most_common('write')}")

    bottleneck_reasons = []
    if avg_global_cpu >= 99.0:
        bottleneck_reasons.append("CPU sob stress extremo")

    if mount_history and any(mount_history):
        print_separator("─")
        header_mt = f"   {'Diretório / LUN':<30} │ {'Uso FS':<6} │ {'Leitura':<11} │ {'Escrita':<11} │ {'IOPS':<7} │ {'Lat':<8} │ {'Util':<6} │ {'Gráfico (Util)':<14} │"
        print(header_mt)
        print("   " + "─" * (len(header_mt) - 3))
        
        all_mts = set()
        for s in mount_history:
            all_mts.update(s.keys())
            
        for mt in sorted(list(all_mts)):
            valid_samples = [s[mt] for s in mount_history if mt in s]
            if not valid_samples:
                continue
                
            avg_u = sum(x['usage'] for x in valid_samples) / len(valid_samples)
            avg_r = sum(x['r_bps'] for x in valid_samples) / len(valid_samples)
            avg_w = sum(x['w_bps'] for x in valid_samples) / len(valid_samples)
            avg_iops = sum(x['iops'] for x in valid_samples) / len(valid_samples)
            avg_lat = sum(x['lat'] for x in valid_samples) / len(valid_samples)
            avg_util = sum(x['util'] for x in valid_samples) / len(valid_samples)
            
            lim_lat = 100.0 if env_type == 'lab' else 25.0
            lim_util = 99.0 if env_type == 'lab' else 95.0
            
            if avg_lat >= lim_lat:
                bottleneck_reasons.append(f"LUN {mt} com Latência Crítica ({avg_lat:.1f}ms)")
            if avg_util >= lim_util:
                bottleneck_reasons.append(f"LUN {mt} com I/O Estrangulado ({avg_util:.1f}%)")
            
            m_cap = format_size(mount_totals.get(mt, 0.0))
            m_name = f"{mt} [{m_cap}]"
            m_name = ("…" + m_name[-29:]) if len(m_name) > 30 else m_name
            
            lat_color = RED if avg_lat > 25.0 else (YELLOW if avg_lat > 10.0 else "")
            util_color = RED if avg_util > 90.0 else (YELLOW if avg_util > 75.0 else "")
            lat_raw = f"{avg_lat/1000:.2f}s" if avg_lat >= 1000 else f"{avg_lat:.1f}ms"
            
            spark = render_sparkline([x['util'] for x in valid_samples], width=14, absolute_max=100.0)
            col_usg = f"{avg_u:.1f}%"
            col_util = f"{avg_util:.1f}%"
            
            print(f"   {m_name:<30} │ {col_usg:>6} │ {format_size(avg_r, True):>11} │ {format_size(avg_w, True):>11} │ {int(avg_iops):>7} │ {lat_color}{lat_raw:>8}{RESET} │ {util_color}{col_util:>6}{RESET} │ {CYAN}{spark}{RESET} │")

    # --- AVALIAÇÃO DE REDES E BUFFERS ---
    net_alerts = []
    if hist_net_stats:
        for net, stats in hist_net_stats.items():
            if stats['fifo'] > 0:
                net_alerts.append(f"[REDE/BUFFER] ESTOURO DE BUFFER (FIFO Overrun) na {net}: {stats['fifo']} pacotes descartados. Aumente os anéis ('ethtool -G {net}').")
                
            max_tpt = max(stats['max_rx'], stats['max_tx'])
            if stats['mtu'] == 1500 and max_tpt > 120000000:
                net_alerts.append(f"[REDE/MTU] Gargalo de Fragmentação ({net}): Tráfego Storage massivo ({format_size(max_tpt, True)}) detectado em MTU Padrão (1500). Valide a aplicação de Jumbo Frames (9000).")

    if bottleneck_reasons or net_alerts:
        print_separator("═")
        print(f" {RED}{BOLD}⚠️  ALERTA DE GARGALO DETECTADO ({env_type.upper()}){RESET}")
        for reason in bottleneck_reasons:
            print(f"   └─ {reason}")
            
        print_separator("─")
        print(f" {BOLD}ANÁLISE CAUSA-RAIZ: DADOS HISTÓRICOS E HARDWARE (Rede, dmesg, SAS PHY, InfiniBand){RESET}")
        
        recent_logs, historical_logs = get_kernel_audit(dmesg_start_lines)
        sas_alerts = get_sas_phy_alerts(sas_baseline, curr_sas)
        ib_alerts = get_ib_alerts(ib_baseline, curr_ib)
        
        if recent_logs or historical_logs or sas_alerts or ib_alerts or net_alerts:
            if net_alerts:
                print(f" {BOLD}AUDITORIA DE REDE E BUFFERS TCP/IP{RESET}")
                for alert in net_alerts:
                    print(f"   {RED}•{RESET} {alert}")
                    
            if sas_alerts:
                print(f" {BOLD}AUDITORIA DE CABOS E HBA (Delta SAS_PHY durante a sessão){RESET}")
                for alert in sas_alerts:
                    print(f"   {RED}•{RESET} {alert}")
                    
            if ib_alerts:
                print(f" {BOLD}AUDITORIA INFINIBAND / RDMA (Delta de Malha){RESET}")
                for alert in ib_alerts:
                    print(f"   {RED}•{RESET} {alert}")
                    
            if recent_logs:
                print(f" {BOLD}FALHAS DE KERNEL (Ocorreram exatamente durante a sessão){RESET}")
                for log in recent_logs:
                    log_trunc = log[:TERMINAL_WIDTH - 8] + '..' if len(log) > TERMINAL_WIDTH - 6 else log
                    print(f"   {RED}•{RESET} {log_trunc}")
                    
            if historical_logs:
                print(f" {BOLD}EVENTOS HISTÓRICOS DE DEGRADAÇÃO (Causas passadas que podem estar ativas){RESET}")
                for log in historical_logs:
                    log_trunc = log[:TERMINAL_WIDTH - 8] + '..' if len(log) > TERMINAL_WIDTH - 6 else log
                    print(f"   {YELLOW}•{RESET} {log_trunc}")
        else:
            print(f"   {GREEN}Nenhuma falha física ativa de hardware, SAS, RDMA ou erro de rede encontrado.{RESET}")
            
    print_separator("═")


# ---------------------------------------------------------------------------
# LOOP PRINCIPAL DO MONITOR
# ---------------------------------------------------------------------------
def run_monitor(
    samples: int, interval: float, target_disks: Optional[List[str]], 
    target_mounts: Optional[List[str]], target_net: Optional[List[str]], 
    export_file: Optional[str], use_pacemaker: bool, 
    ib_devices: Optional[List[str]], show_sensors: bool, 
    use_idrac_log: bool, sensor_interval: float, idrac_types: List[str], 
    env_type: str, show_multipath: bool
) -> None:
    
    dmesg_start_lines = 0
    try:
        dmesg_start_lines = int(os.popen("dmesg | wc -l 2>/dev/null").read().strip())
    except Exception:
        pass

    sas_baseline = get_sas_phy_stats()
    ib_baseline = get_ib_stats(ib_devices)
    hostname = get_hostname()
    
    prev_cpu, _, prev_mem, prev_disk, prev_mount, prev_net = get_system_data(target_disks, target_mounts, target_net)
    prev_ib = get_ib_stats(ib_devices)
    
    hist_time, hist_cpu, hist_mem, hist_mounts = [], [], [], []
    sys_mount_totals = {}
    prev_procs, hist_procs, hist_sas, hist_ib, hist_net_stats = {}, [], [], [], {}
    is_root = os.geteuid() == 0 
    
    print("\033[?1049h", end="")
    try:
        for current_sample in range(1, samples + 1):
            curr_cpu, curr_load, curr_mem, curr_disk, curr_mount, curr_net = get_system_data(target_disks, target_mounts, target_net)
            curr_procs, top_cpu_procs, top_mem_procs, top_read_procs, top_write_procs = get_top_processes(prev_procs, interval)
            curr_sas = get_sas_phy_stats()
            curr_ib = get_ib_stats(ib_devices)
            
            c_p = f"{top_cpu_procs[0]['comm']}[{top_cpu_procs[0]['pid']}]" if top_cpu_procs and top_cpu_procs[0]['cpu'] > 1.0 else "-"
            m_p = f"{top_mem_procs[0]['comm']}[{top_mem_procs[0]['pid']}]" if top_mem_procs and top_mem_procs[0]['mem'] > 0 else "-"
            r_p = f"{top_read_procs[0]['comm']}[{top_read_procs[0]['pid']}]" if top_read_procs and top_read_procs[0]['read'] > 0 else "-"
            w_p = f"{top_write_procs[0]['comm']}[{top_write_procs[0]['pid']}]" if top_write_procs and top_write_procs[0]['write'] > 0 else "-"
            hist_procs.append({'cpu': c_p, 'mem': m_p, 'read': r_p, 'write': w_p})
            
            t_base_errs = sum(v['errors'] for v in sas_baseline.values()) if sas_baseline else 0
            t_curr_errs = sum(v['errors'] for v in curr_sas.values()) if curr_sas else 0
            delta_sas_errs = t_curr_errs - t_base_errs
            degraded_sas_links = sum(1 for v in curr_sas.values() if v.get('degraded', False)) if curr_sas else 0
            hist_sas.append({'delta_errs': delta_sas_errs, 'degraded': degraded_sas_links})
            
            ib_sym_errs, ib_discs = 0, 0
            if curr_ib:
                for ib_dev, c_data in curr_ib.items():
                    p_data = ib_baseline.get(ib_dev, {'errors': {}})
                    ib_sym_errs += c_data['errors'].get('symbol_error', 0) - p_data.get('errors', {}).get('symbol_error', 0)
                    ib_discs += c_data['errors'].get('port_xmit_discards', 0) - p_data.get('errors', {}).get('port_xmit_discards', 0)
            hist_ib.append({'sym_errs': ib_sym_errs, 'discards': ib_discs})

            hist_time.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            sys_mem_bytes = curr_mem[1]
            
            print("\033[2J\033[H", end="")
            print(f"{CYAN}╭{'─' * (TERMINAL_WIDTH - 2)}╮{RESET}")
            print(f"{CYAN}│{RESET} {BOLD}{f'MONITOR E TROUBLESHOOTING RHEL 8+ - {hostname}'.center(TERMINAL_WIDTH - 4)}{RESET} {CYAN}│{RESET}")
            print(f"{CYAN}│{RESET} {f'[ Analise de Throughput | Latency | Processos e Gargalos ]'.center(TERMINAL_WIDTH - 4)} {CYAN}│{RESET}")
            print(f"{CYAN}│{RESET} {f'Amostra {current_sample}/{samples} (Atualização: {interval}s)'.center(TERMINAL_WIDTH - 4)} {CYAN}│{RESET}")
            print(f"{CYAN}╰{'─' * (TERMINAL_WIDTH - 2)}╯{RESET}")
            
            if use_pacemaker:
                ha_status, ha_quorum, ha_node = get_pacemaker_status_cached()
                status_color = GREEN if 'ONLINE' in ha_status else YELLOW
                quorum_color = GREEN if ha_quorum == 'OK' else RED
                print(f" {BOLD}⚡ CLUSTER HA (Pacemaker){RESET} │ Status: {status_color}{ha_status:<16}{RESET} │ Nó: {CYAN}{ha_node:<10}{RESET} │ Quorum: {quorum_color}{ha_quorum}{RESET}")
                print_separator("─")

            sample_cpu = {}
            sorted_cores = sorted(curr_cpu.keys(), key=lambda x: int(x[3:]))
            cols = 4 if len(sorted_cores) > 16 else 2
            bar_width = 12 if len(sorted_cores) > 16 else 40
            rows = (len(sorted_cores) + cols - 1) // cols
            cores_cols = [[] for _ in range(cols)]

            global_act, global_tot, global_iow = 0, 0, 0
            for idx, core in enumerate(sorted_cores):
                act_diff = curr_cpu[core][0] - prev_cpu[core][0]
                idl_diff = curr_cpu[core][1] - prev_cpu[core][1]
                iow_diff = curr_cpu[core][2] - prev_cpu[core][2]
                
                tot = act_diff + idl_diff + iow_diff
                global_act += act_diff
                global_tot += tot
                global_iow += iow_diff
                
                load = (act_diff / tot) * 100 if tot > 0 else 0.0
                sample_cpu[core] = load
                cores_cols[idx // rows].append(f" {core:<5}│ {render_progress_bar(load, max_width=bar_width, show_suffix=False)}")
            
            hist_cpu.append(sample_cpu)
            hist_mem.append(curr_mem[0])
            
            g_cpu = (global_act / global_tot) * 100 if global_tot > 0 else 0.0
            g_iow = (global_iow / global_tot) * 100 if global_tot > 0 else 0.0
            
            w_col = RED if g_iow > 20.0 else YELLOW if g_iow > 5.0 else ""
            iow_display = f"{w_col}{g_iow:.1f}%{RESET}"
            cpu_head = f"CPU (Load: {curr_load} | I/O Wait: {iow_display}{BOLD})"
            padding_head = LEFT_COL_WIDTH + (len(w_col) + len(RESET) if w_col else 0)
            
            print(f" {BOLD}{cpu_head:<{padding_head}}{RESET}│ {render_progress_bar(g_cpu, max_width=50)}")
            print_separator("─")
            
            for r in range(rows):
                r_parts = [cores_cols[c][r] if r < len(cores_cols[c]) else " " * (15 + bar_width) for c in range(cols)]
                print(" │".join(r_parts))
                
            print_separator("─")
            
            mem_head = f"RAM [{format_size(curr_mem[1])}]"
            print(f" {BOLD}{mem_head:<{LEFT_COL_WIDTH}}{RESET}│ {render_progress_bar(curr_mem[0], max_width=50)}")
            
            if curr_mem[3] > 0:
                swap_head = f"SWAP [{format_size(curr_mem[3])}]"
                swap_col = RED if curr_mem[2] > 20.0 else YELLOW if curr_mem[2] > 5.0 else GREEN
                print(f" {BOLD}{swap_head:<{LEFT_COL_WIDTH}}{RESET}│ {swap_col}{render_progress_bar(curr_mem[2], max_width=25, show_suffix=False)} Uso causa gargalo de I/O Severo{RESET}")
            
            if curr_ib and prev_ib:
                print_separator("─")
                for ib_dev in curr_ib:
                    if ib_dev in prev_ib:
                        c_ib, p_ib = curr_ib[ib_dev], prev_ib[ib_dev]
                        ib_rx_diff = (c_ib['rx_bytes'] - p_ib['rx_bytes']) / interval
                        ib_tx_diff = (c_ib['tx_bytes'] - p_ib['tx_bytes']) / interval
                        
                        s_err = c_ib['errors'].get('symbol_error', 0) - p_ib['errors'].get('symbol_error', 0)
                        disc = c_ib['errors'].get('port_xmit_discards', 0) - p_ib['errors'].get('port_xmit_discards', 0)
                        
                        err_col = RED if s_err > 0 else GREEN
                        disc_col = RED if disc > 0 else GREEN
                        err_str = f"SymErr: {err_col}{s_err}{RESET} │ Desc: {disc_col}{disc}{RESET}"
                        
                        ib_name = ib_dev[:8]
                        print(f" {BOLD}🌐 REDE INFINIBAND ({ib_name:<8}){RESET} │ RX: {format_size(ib_rx_diff, True):>11} │ TX: {format_size(ib_tx_diff, True):>11} │ {err_str}")

            if target_net:
                print_separator("═")
                print(f" {BOLD}{'INTERFACE DE REDE (MTU e Buffers Ethernet)':<40} │ {'RX (Recepção)':<14} │ {'TX (Envio)':<14} │ {'PERDAS (Drop)':<12} │ {'FIFO (Overrun)':<11}{RESET}")
                print_separator("─")
                for net in target_net:
                    if net in curr_net and net in prev_net:
                        c_n, p_n = curr_net[net], prev_net[net]
                        rx_bps = (c_n[0] - p_n[0]) / interval
                        tx_bps = (c_n[1] - p_n[1]) / interval
                        
                        fifo_errs = (c_n[6] - p_n[6]) + (c_n[7] - p_n[7])
                        if net not in hist_net_stats:
                            hist_net_stats[net] = {'fifo': 0, 'max_rx': 0, 'max_tx': 0, 'mtu': c_n[8]}
                        
                        hist_net_stats[net]['fifo'] += fifo_errs
                        hist_net_stats[net]['max_rx'] = max(hist_net_stats[net]['max_rx'], rx_bps)
                        hist_net_stats[net]['max_tx'] = max(hist_net_stats[net]['max_tx'], tx_bps)

                        d_col = RED if (c_n[2] - p_n[2] > 0 or c_n[3] - p_n[3] > 0) else ""
                        f_col = RED if fifo_errs > 0 else ""
                        
                        mtu_val = c_n[8]
                        mtu_col = RED if mtu_val == 1500 and (rx_bps > 120000000 or tx_bps > 120000000) else ""
                        mtu_display = f"{mtu_col}{mtu_val}{RESET}" if mtu_col else str(mtu_val)
                        
                        base_str = f"{net} (MTU:{mtu_val})"
                        base_str = base_str[-39:] if len(base_str) > 40 else base_str
                        print_str = base_str.replace(str(mtu_val), mtu_display)
                        
                        padding_len = max(0, 40 - len(base_str))
                        padding = " " * padding_len
                        
                        drp_str = f"{c_n[2]-p_n[2]}/{c_n[3]-p_n[3]}"
                        ffo_str = f"{c_n[6]-p_n[6]}/{c_n[7]-p_n[7]}"
                        
                        print(f" {print_str}{padding} │ {format_size(rx_bps, True):>14} │ {format_size(tx_bps, True):>14} │ {d_col}{drp_str:<12}{RESET} │ {f_col}{ffo_str:<11}{RESET}")

            if curr_sas:
                print_separator("─")
                err_col = RED if delta_sas_errs > 0 else GREEN
                deg_col = RED if hist_sas[-1]['degraded'] > 0 else GREEN
                print(f" {BOLD}🔌 CONTROLADORA HBA/SAS (Monitoramento de Cabos){RESET} │ Erros Físicos Gerados na Sessão: {err_col}{delta_sas_errs}{RESET} │ Links Degradados: {deg_col}{hist_sas[-1]['degraded']}{RESET}")

            # -----------------------------------------------------------------------
            # BLOCO: TOP PROCESSOS
            # -----------------------------------------------------------------------
            print_separator("═")
            print(f" {BOLD}TOP PROCESSOS (Consumo em Tempo Real por PID){RESET}")
            print_separator("─")
            
            cpu_items = []
            for i, p in enumerate(top_cpu_procs):
                if p['cpu'] > 0.1:
                    item_str = f"{i+1}: {p['comm'][:10]}[{p['pid']}] ({p['cpu']:.1f}%)"
                    cpu_items.append(item_str[:31].ljust(32))
            c_str = "".join(cpu_items)
            
            mem_items = []
            for i, p in enumerate(top_mem_procs):
                if p['mem'] > 0:
                    item_str = f"{i+1}: {p['comm'][:10]}[{p['pid']}] ({format_size(p['mem'])})"
                    mem_items.append(item_str[:31].ljust(32))
            m_str = "".join(mem_items)
            
            read_items = []
            for i, p in enumerate(top_read_procs):
                if p['read'] > 0:
                    item_str = f"{i+1}: {p['comm'][:10]}[{p['pid']}] ({format_size(p['read'], True)})"
                    read_items.append(item_str[:31].ljust(32))
            r_str = "".join(read_items)
            
            write_items = []
            for i, p in enumerate(top_write_procs):
                if p['write'] > 0:
                    item_str = f"{i+1}: {p['comm'][:10]}[{p['pid']}] ({format_size(p['write'], True)})"
                    write_items.append(item_str[:31].ljust(32))
            w_str = "".join(write_items)
            
            e_msg = "0.0 B/s (Sem atividade no ciclo)" if is_root else "0.0 B/s (Requer sudo)"

            print(f" {RED}{'🔥 TOP CPU':<15}{RESET} │ {c_str if c_str else 'Nenhum consumo expressivo'}")
            print(f" {GREEN}{'🧠 TOP RAM':<15}{RESET} │ {m_str if m_str else 'Nenhum consumo expressivo'}")
            print(f" {CYAN}{'📖 TOP LEITURA':<15}{RESET} │ {r_str if r_str else e_msg}")
            print(f" {YELLOW}{'💾 TOP ESCRITA':<15}{RESET} │ {w_str if w_str else e_msg}")

            # -----------------------------------------------------------------------
            # BLOCO: Sensores
            # -----------------------------------------------------------------------
            if show_sensors or use_idrac_log:
                sensors_data = get_hardware_sensors_cached(sensor_interval, use_idrac_log, idrac_types)
                if sensors_data:
                    print_separator("═")
                    if use_idrac_log:
                        print(f" {BOLD}TELEMETRIA EXCLUSIVA iDRAC (Via Arquivo de Compliance) - Monitoramento de Hardware{RESET}")
                    else:
                        print(f" {BOLD}SENSORES DE HARDWARE DO HOST (Sysfs / Discos / GPUs) - Throttling Prevention{RESET}")
                    print_separator("─")
                    
                    s_strs = []
                    for n, v, l in sensors_data:
                        n_str = n[:26] + ".." if len(n) > 28 else n
                        v_col = RED if l == 2 else (YELLOW if l == 1 else GREEN)
                        stat_col = RED + "[CRIT]" if l == 2 else (YELLOW + "[WARN]" if l == 1 else GREEN + "[ OK ]")
                        s_strs.append(f" {n_str:<28} │ {v_col}{v[:12]:>12}{RESET} {stat_col}{RESET}")
                        
                    for i in range(0, len(s_strs), 2):
                        col1 = s_strs[i]
                        col2 = s_strs[i+1] if i+1 < len(s_strs) else ""
                        print(f"{col1:<57} ║ {col2}")
                elif use_idrac_log:
                    print_separator("═")
                    print(f" {BOLD}TELEMETRIA EXCLUSIVA iDRAC{RESET}")
                    print_separator("─")
                    print(f" {YELLOW}Aviso: Nenhuma telemetria iDRAC encontrada para os tipos solicitados.{RESET}")

            # -----------------------------------------------------------------------
            # BLOCO: Topologia Multipath SAN
            # -----------------------------------------------------------------------
            if show_multipath:
                mp_topology = get_multipath_topology()
                if mp_topology:
                    print_separator("═")
                    print(f" {BOLD}TOPOLOGIA MULTIPATH SAN (I/O Distribuído por Caminho Físico){RESET}")
                    print_separator("─")
                    for dm, info in sorted(mp_topology.items()):
                        dm_r, dm_w, dm_iops = calc_device_io(dm, curr_disk, prev_disk, interval)
                        vol_name = info.get('name', 'Unknown')
                        vol_title = f"Volume Virtual: {vol_name} ({dm})"
                        print(f" {BOLD}{vol_title:<40}{RESET} │ R: {format_size(dm_r, True):>11} │ W: {format_size(dm_w, True):>11} │ {int(dm_iops):>6} IOPS")
                        
                        slaves = sorted(info['slaves'])
                        for i, slave in enumerate(slaves):
                            s_r, s_w, s_iops = calc_device_io(slave, curr_disk, prev_disk, interval)
                            
                            is_active = s_r > 0 or s_w > 0
                            status_str = f"{GREEN}Ativo/I-O{RESET}" if is_active else f"{YELLOW}Standby{RESET}"
                            slave_title = f"{slave} ({status_str})"
                            
                            prefix = "└─>" if i == len(slaves) - 1 else "├─>"
                            padding = 34 + (len(GREEN) + len(RESET) if is_active else len(YELLOW) + len(RESET))
                            
                            print(f"   {prefix} {slave_title:<{padding}} │ R: {format_size(s_r, True):>11} │ W: {format_size(s_w, True):>11} │ {int(s_iops):>6} IOPS")

            # -----------------------------------------------------------------------
            # BLOCO: Armazenamento e LUNs
            # -----------------------------------------------------------------------
            if target_mounts:
                for m, data in curr_mount.items():
                    sys_mount_totals[m] = data[1]
                    
                print_separator("═")
                print(f" {BOLD}ARMAZENAMENTO (Análise de Latency, Throughput e Utilização de LUNs){RESET}")
                print_separator("─")
                
                for mt in target_mounts:
                    if mt in curr_mount and mt in prev_mount:
                        c_io = curr_mount[mt][2]
                        p_io = prev_mount[mt][2]
                        r_bps, w_bps, r_iops, w_iops, lat_ms, util_pct = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
                        
                        if c_io[0] is not None and p_io[0] is not None:
                            r_bps = (c_io[0] - p_io[0]) / interval
                            w_bps = (c_io[1] - p_io[1]) / interval
                            t_iops = ((c_io[2] - p_io[2]) + (c_io[3] - p_io[3])) / interval
                            
                            if t_iops > 0:
                                lat_ms = ((c_io[4] - p_io[4]) + (c_io[5] - p_io[5])) / (t_iops * interval)
                                
                            util_pct = min(((c_io[6] - p_io[6]) / (interval * 1000.0)) * 100.0, 100.0)
                            
                        hist_mounts.append({
                            mt: {
                                'usage': curr_mount[mt][0], 
                                'r_bps': r_bps, 
                                'w_bps': w_bps, 
                                'iops': t_iops if c_io[0] else 0, 
                                'lat': lat_ms, 
                                'util': util_pct
                            }
                        })
                        
                        cap_str = f"[{format_size(curr_mount[mt][1])}]"
                        d_name = mt[-(max(10, LEFT_COL_WIDTH - 2 - len(cap_str)) - 1):]
                        if len(mt) > len(d_name):
                            d_name = "…" + d_name
                            
                        mt_head = f"{d_name} {cap_str}"
                        print(f" {BOLD}{mt_head:<{LEFT_COL_WIDTH}}{RESET}│ {render_progress_bar(curr_mount[mt][0], max_width=50)}")
                        
                        if c_io[0] is not None:
                            lat_col = RED if lat_ms > 25.0 else (YELLOW if lat_ms > 10.0 else "")
                            lat_disp = f"{lat_ms/1000:.2f}s" if lat_ms >= 1000 else f"{lat_ms:.0f}ms"
                            
                            utl_col = RED if util_pct > 90.0 else (YELLOW if util_pct > 75.0 else "")
                            utl_disp = f"{util_pct:.1f}%"
                            
                            print(f" {CYAN}{'└─> I/O & Perf':<{LEFT_COL_WIDTH}}{RESET}│ R:{format_size(r_bps, True):>11} │ W:{format_size(w_bps, True):>11} │ {int(t_iops if c_io[0] else 0):>6} IOPS │ Lat:{lat_col}{lat_disp:>7}{RESET} │ Utl:{utl_col}{utl_disp:>6}{RESET}")
                        else:
                            print(f" {CYAN}{'└─> I/O & Perf':<{LEFT_COL_WIDTH}}{RESET}│ (Volume de Rede / Virtual - I/O em bloco indisponível)")
            
            print_separator("═")
            print(f" {YELLOW}Pressione Ctrl+C para encerrar.{RESET}")
            
            prev_cpu, prev_disk, prev_mount, prev_net = curr_cpu, curr_disk, curr_mount, curr_net
            prev_ib, prev_procs = curr_ib, curr_procs
            time.sleep(interval)
            
    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?1049l", end="")
        print(f"\n{GREEN}Monitoramento finalizado.{RESET}")
        
        display_summary_report(
            hist_cpu, hist_mem, hist_mounts, sys_mem_bytes, sys_mount_totals, 
            hist_procs, env_type, dmesg_start_lines, sas_baseline, curr_sas, 
            ib_baseline, curr_ib, hist_net_stats
        )
        if export_file:
            export_to_csv(
                export_file, hist_time, hist_cpu, hist_mem, hist_mounts, 
                hist_procs, hist_sas, hist_ib
            )


# ---------------------------------------------------------------------------
# EXECUÇÃO E PARSER
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Monitor de Performance e Troubleshoot I/O - RHEL 8+ / HPC.")
    parser.add_argument('-samples', type=int, default=60, help="Ciclos de coleta.")
    parser.add_argument('-interval', type=float, default=1.0, help="Intervalo (s).")
    parser.add_argument('-disks', type=str, nargs='+', help="Discos locais (ex: sda).")
    parser.add_argument('--all-mounts', action='store_true', help="Inclui montagens básicas (/, /boot).")
    parser.add_argument('-mounts', type=str, nargs='*', help="Pontos específicos de montagem.")
    parser.add_argument('-net', type=str, nargs='+', help="Interfaces de rede tradicionais (ex: eth0).")
    parser.add_argument('--export-csv', type=str, help="Caminho do arquivo CSV para exportação.")
    
    parser.add_argument('--env', type=str, choices=['prod', 'lab'], default='prod', help="Define a agressividade dos alertas de auditoria. Padrão: prod.")
    parser.add_argument('--multipath', action='store_true', help="Ativa a visualização da árvore de topologia SAN/LUNs.")
    
    parser.add_argument('--pacemaker', action='store_true', help="Ativa o monitoramento do cluster HA (Pacemaker / Quorum).")
    parser.add_argument('--infiniband', type=str, nargs='+', help="Ativa monitoramento de RDMA em redes InfiniBand.")
    parser.add_argument('--sensores', action='store_true', help="Ativa a telemetria do Host (Sysfs, Discos, GPUs).")
    
    parser.add_argument('--racadm', '--idrac-log', dest='idrac_log', action='store_true', help="Ativa a telemetria lendo o log local da iDRAC.")
    parser.add_argument('--sensor-interval', type=float, default=60.0, help="Intervalo de cache para leitura do Log. Padrão: 60s.")
    parser.add_argument('--idrac-types', type=str, nargs='+', default=['TEMPERATURE'], help="Tipos de sensores da iDRAC a exibir.")
    
    args = parser.parse_args()
    
    if args.interval <= 0:
        print(f"{RED}Erro: O intervalo deve ser maior que 0.{RESET}")
        return
        
    mounts_to_monitor = args.mounts if args.mounts is not None else get_physical_mounts(args.all_mounts)
    
    run_monitor(
        samples=args.samples, 
        interval=args.interval, 
        target_disks=args.disks, 
        target_mounts=mounts_to_monitor, 
        target_net=args.net, 
        export_file=args.export_csv, 
        use_pacemaker=args.pacemaker, 
        ib_devices=args.infiniband, 
        show_sensors=args.sensores, 
        use_idrac_log=args.idrac_log, 
        sensor_interval=args.sensor_interval, 
        idrac_types=args.idrac_types, 
        env_type=args.env, 
        show_multipath=args.multipath
    )


if __name__ == "__main__":
    main()
