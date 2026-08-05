#!/usr/bin/env python3
"""
InfiniBand Port, Performance Counter and Latency Monitor para RHEL 8+
Refatorado para:
 - Uso de os.popen para testes ativos (ibping)
 - Prints nativos em linha única (preparado para customização de logs)
 - Filtragem de HCAs não utilizados (mlx5_2, mlx5_3)
 - Execução por duração determinada
 - Identificação clara de Topologia em linha única
 - Feedback positivo ao final da execução (Health Check)
"""

import os
import sys
import time
import re

# --- CONFIGURAÇÕES ---
DURATION_SEC = 60          # Duração total da execução do script em segundos
CHECK_INTERVAL_SEC = 5     # Intervalo de amostragem em segundos
LATENCY_TARGET_LID = "2"   # Substitua pelo LID do servidor de destino do ibping

# Limites (Thresholds)
SYMBOL_ERROR_ALERT_THRESHOLD = 5
PORT_XMIT_WAIT_ALERT_THRESHOLD = 1000
LATENCY_ALERT_THRESHOLD_MS = 0.500

# Lista de HCAs que devem ser ignorados na varredura (disabled by default)
IGNORED_DEVICES = ["mlx5_2", "mlx5_3"]

class PortStateTracker:
    def __init__(self, dev: str, port: str):
        self.dev = dev
        self.port = port
        self.logical_state = "UNKNOWN"
        self.physical_state = "UNKNOWN"
        self.last_symbol_errors = 0
        self.last_xmit_wait = 0
        self.last_latency_ms = 0.0
        self.first_run = True
        
        # Flag para rastrear se alguma anomalia aconteceu nesta porta
        self.had_anomalies = False 

    def update_and_check(self, state: str, phys_state: str, symbol_errors: int, xmit_wait: int, latency_ms: float):
        # 1. Transições de estado lógico
        if not self.first_run and self.logical_state != state:
            msg = f"[{self.dev} P{self.port}] Lógico: {self.logical_state}->{state}"
            if state == "ACTIVE":
                print(f"INFO | RECOVERED | {msg}")
            else:
                self.had_anomalies = True
                print(f"ERROR | CRITICAL | {msg}")

        # 2. Transições de estado físico
        if not self.first_run and self.physical_state != phys_state:
            msg = f"[{self.dev} P{self.port}] Físico: {self.physical_state}->{phys_state}"
            if phys_state == "LinkUp":
                print(f"INFO | PHYS UP | {msg}")
            else:
                self.had_anomalies = True
                print(f"WARN | PHYS DOWN | {msg}")

        # 3. Incremento de Symbol Error Counter
        if not self.first_run:
            symbol_delta = symbol_errors - self.last_symbol_errors
            if symbol_delta > 0:
                self.had_anomalies = True
                level = "WARN" if symbol_delta < SYMBOL_ERROR_ALERT_THRESHOLD else "ERROR"
                print(f"{level} | SYMBOL ERR | [{self.dev} P{self.port}] +{symbol_delta} erros no intervalo (Total: {symbol_errors})")

        # 4. Incremento de Port Xmit Wait (Congestionamento)
        if not self.first_run:
            xmit_wait_delta = xmit_wait - self.last_xmit_wait
            if xmit_wait_delta > PORT_XMIT_WAIT_ALERT_THRESHOLD:
                self.had_anomalies = True
                print(f"WARN | CONGESTION | [{self.dev} P{self.port}] +{xmit_wait_delta} xmit_wait no intervalo (Total: {xmit_wait})")

        # 5. Degradação de Latência
        if not self.first_run and latency_ms > 0:
            if latency_ms > LATENCY_ALERT_THRESHOLD_MS:
                self.had_anomalies = True
                print(f"WARN | HIGH LATENCY | [{self.dev} P{self.port}] RTT: {latency_ms:.3f} ms")

        # Atualiza o histórico
        self.logical_state = state
        self.physical_state = phys_state
        self.last_symbol_errors = symbol_errors
        self.last_xmit_wait = xmit_wait
        self.last_latency_ms = latency_ms
        self.first_run = False


def read_sys_file(path: str, default: str = "0") -> str:
    """Lê um arquivo do sistema sysfs."""
    try:
        if os.path.exists(path):
            with open(path, 'r') as f:
                return f.read().strip()
    except Exception as e:
        print(f"DEBUG | Erro leitura sysfs: {path} - {e}")
    return str(default)


def print_lid_topology(devices: dict):
    """
    Imprime a topologia (Local LID e SM LID) em uma linha única por interface.
    """
    ib_dir = "/sys/class/infiniband"
    
    for dev, ports in devices.items():
        for port in ports:
            port_path = os.path.join(ib_dir, dev, "ports", port)
            
            local_lid_hex = read_sys_file(os.path.join(port_path, "lid"), "0x0")
            sm_lid_hex = read_sys_file(os.path.join(port_path, "sm_lid"), "0x0")
            
            local_lid = int(local_lid_hex, 16)
            sm_lid = int(sm_lid_hex, 16)
            
            sm_status = str(sm_lid) if sm_lid != 0 else "0 (FALHA/INATIVO)"
            
            print(f"TOPOLOGY | [{dev} P{port}] Host LID: {local_lid} | Switch SM LID: {sm_status}")


def measure_latency_popen(hca_dev: str, hca_port: str, dest_lid: str) -> float:
    """Mede a latência usando ibping via os.popen."""
    cmd = f"ibping -c 3 -C {hca_dev} -P {hca_port} -L {dest_lid} 2>/dev/null"
    
    try:
        with os.popen(cmd) as pipe:
            output = pipe.read()
        
        match = re.search(r'min/avg/max\s*=\s*\d+\.\d+/(\d+\.\d+)/\d+\.\d+\s*ms', output)
        if match:
            return float(match.group(1))
            
    except Exception as e:
        pass # Silenciado intencionalmente para não poluir logs saudáveis
        
    return -1.0


def get_ib_devices() -> dict:
    """Mapeia dispositivos ativos, ignorando os bloqueados na lista."""
    ib_dir = "/sys/class/infiniband"
    devices = {}
    
    if not os.path.exists(ib_dir):
        print(f"ERROR | Sysfs path not found: {ib_dir}")
        return devices

    for dev in os.listdir(ib_dir):
        if dev in IGNORED_DEVICES:
            continue
            
        dev_ports_dir = os.path.join(ib_dir, dev, "ports")
        if os.path.exists(dev_ports_dir):
            devices[dev] = {}
            for port in os.listdir(dev_ports_dir):
                devices[dev][port] = PortStateTracker(dev, port)
                
    return devices


def monitor_loop(devices: dict, duration: int, interval: int):
    """Executa a checagem por um tempo determinado."""
    ib_dir = "/sys/class/infiniband"
    start_time = time.time()
    
    print(f"INFO | START | Monitoramento iniciado por {duration} segundos")
    
    while (time.time() - start_time) < duration:
        for dev, ports in list(devices.items()):
            for port, tracker in ports.items():
                port_path = os.path.join(ib_dir, dev, "ports", port)
                
                # Leitura de Estados
                state = read_sys_file(os.path.join(port_path, "state"), "Down")
                if "ACTIVE" in state:
                    state = "ACTIVE"
                elif "Down" in state or "1:" in state:
                    state = "DOWN"

                phys_state = read_sys_file(os.path.join(port_path, "phys_state"), "Disabled")
                if "LinkUp" in phys_state:
                    phys_state = "LinkUp"

                # Leitura de Contadores
                symbol_errors = int(read_sys_file(os.path.join(port_path, "counters", "symbol_error"), "0"))
                xmit_wait = int(read_sys_file(os.path.join(port_path, "counters", "port_xmit_wait"), "0"))

                # Teste Ativo
                current_latency = -1.0
                if state == "ACTIVE":
                    current_latency = measure_latency_popen(dev, port, LATENCY_TARGET_LID)

                # Processar dados
                tracker.update_and_check(state, phys_state, symbol_errors, xmit_wait, current_latency)

        time.sleep(interval)
        
    print("INFO | STOP | Tempo limite atingido")
    
    # NOVO: Avaliação de Saúde Final
    for dev, ports in devices.items():
        for port, tracker in ports.items():
            if not tracker.had_anomalies:
                print(f"SUCCESS | HEALTH_CHECK | [{dev} P{port}] Sem erros fisicos, congestionamento ou quedas (Latencia < {LATENCY_ALERT_THRESHOLD_MS}ms).")
            else:
                print(f"WARN | HEALTH_CHECK | [{dev} P{port}] Apresentou anomalias durante a execucao. Revise os logs acima.")


if __name__ == "__main__":
    ib_devices = get_ib_devices()
    
    if not ib_devices:
        print("ERROR | INIT | Nenhum adaptador InfiniBand mapeado")
        sys.exit(1)

    print_lid_topology(ib_devices)
    
    try:
        monitor_loop(ib_devices, DURATION_SEC, CHECK_INTERVAL_SEC)
    except KeyboardInterrupt:
        print("\nINFO | STOP | Cancelado pelo usuario")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR | SYSTEM | Falha na execução: {e}")
        sys.exit(1)
