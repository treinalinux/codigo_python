#!/usr/bin/env python3
"""
Leitor Humano de Relatórios ibdiagnet (RHEL 8 / Mellanox)
Versão Assistente: Parseamento inteligente e manuais de mitigação NVIDIA integrados.
"""

import os
import sys
import time
import re

LOG_FILE = "/var/tmp/ibdiagnet2/ibdiagnet2.log"

def extract_node_info(line):
    """Tenta extrair Nome e LID das linhas complexas do ibdiagnet usando Regex."""
    name_match = re.search(r'Node Name:\s*([^,]+)', line)
    lid_match = re.search(r'LID:\s*(\d+)', line)
    
    if name_match and lid_match:
        name = name_match.group(1).strip()
        lid = lid_match.group(1)
        return f"{name} (LID: {lid})"
    
    return line.split(":", 1)[-1].strip() if ":" in line and line.startswith("-") else line


def analyze_ibdiagnet_log():
    if not os.path.exists(LOG_FILE):
        print(f"ERRO | Arquivo não encontrado: {LOG_FILE}")
        print("DICA | Execute 'sudo ibdiagnet' para gerar um novo relatório.")
        sys.exit(1)

    file_mtime = os.path.getmtime(LOG_FILE)
    run_date = time.strftime('%d/%m/%Y às %H:%M:%S', time.localtime(file_mtime))

    duplications, routing, downgrades, general_errors = set(), set(), set(), set()
    master_sms, standby_sms = [], []

    # Leitura e parsing do arquivo
    with open(LOG_FILE, 'r') as file:
        for line in file:
            line = line.strip()
            lower_line = line.lower()
            
            if "master sm" in lower_line:
                master_sms.append(extract_node_info(line))
            elif "standby sm" in lower_line:
                standby_sms.append(extract_node_info(line))

            is_error = "-E-" in line
            is_warning = "-W-" in line

            if is_error or is_warning:
                clean_line = line.split("-E-", 1)[-1].strip() if is_error else line.split("-W-", 1)[-1].strip()
                lower_clean = clean_line.lower()

                if "duplicate" in lower_clean or "dup " in lower_clean:
                    duplications.add(clean_line)
                elif "routing" in lower_clean or "unreach" in lower_clean:
                    routing.add(clean_line)
                elif "downgrade" in lower_clean:
                    downgrades.add(clean_line)
                elif is_error:
                    general_errors.add(clean_line)

    # ==========================================
    # SAÍDA FORMATADA (TELA)
    # ==========================================
    print("\n" + "=" * 80)
    print(f"📊 RELATÓRIO DE SAÚDE DA MALHA INFINIBAND")
    print(f"🕒 Gerado pelo ibdiagnet em: {run_date}")
    print("=" * 80)

    print("\n👑 CÉREBRO DA REDE (SUBNET MANAGERS):")
    if master_sms:
        for sm in master_sms:
            print(f"  -> MASTER  : {sm}")
    else:
        print("  -> MASTER  : [ALERTA CRÍTICO] Não localizado! Roteamento pode estar offline.")

    if standby_sms:
        for sm in standby_sms:
            print(f"  -> STANDBY : {sm}")
    print("-" * 80)

    total_issues = len(duplications) + len(routing) + len(downgrades) + len(general_errors)
    
    if total_issues == 0:
        print("\n✅ STATUS GERAL: EXCELENTE")
        print("  A malha está perfeitamente saudável. Nenhum erro de roteamento,")
        print("  duplicação de GUID/LID ou rebaixamento físico de cabos detectado.")
        print("=" * 80 + "\n")
        sys.exit(0)
    
    print(f"\n⚠️ STATUS GERAL: ATENÇÃO REQUERIDA ({total_issues} anomalias detectadas)")

    def print_block(title, items, action_lines):
        if items:
            print(f"\n{title} ({len(items)} ocorrências):")
            items_list = list(items)
            for item in items_list[:10]:
                print(f"  - {item}")
            if len(items_list) > 10:
                print(f"  ... e mais {len(items_list) - 10} similares (Consulte o log original).")
            
            print("\n  💡 MANUAL DE MITIGAÇÃO NVIDIA:")
            for action in action_lines:
                print(f"     {action}")

    # --- Dicas Oficiais NVIDIA/Mellanox ---
    
    print_block(
        "🚨 DUPLICAÇÃO DE IDENTIFICADORES (GUID/LID)", 
        duplications, 
        [
            "1. Identifique a porta física do nó problemático na lista acima.",
            "2. Acesse via SSH o switch MLNX-OS onde essa porta está conectada.",
            "3. Isole a porta administrativamente (Comandos: 'interface ib 1/x' -> 'shutdown') para estabilizar a malha.",
            "4. Verifique se há hypervisors clonando vGUIDs idênticos em VMs ou troque o HCA do servidor afetado."
        ]
    )
    
    print_block(
        "🚨 FALHAS DE ROTEAMENTO (Routing / Unreachable)", 
        routing, 
        [
            "1. Acesse via SSH o switch listado como MASTER SM no topo deste relatório.",
            "2. Force um recálculo total da malha (Heavy Sweep) reiniciando o serviço OpenSM.",
            "   (Comandos MLNX-OS: execute 'no ib sm' aguarde 3 segundos, e execute 'ib sm').",
            "3. Se persistir, valide se o algoritmo de roteamento ('show ib sm') suporta sua topologia (ex: minhop vs fattree)."
        ]
    )
    
    print_block(
        "⚠️ DEGRADAÇÃO FÍSICA (Link Downgrade)", 
        downgrades, 
        [
            "1. A porta negociou abaixo da velocidade nominal (ex: 1X ao invés de 4X) devido a corrupção de sinal.",
            "2. Tente um reset lógico pelo RHEL 8: execute 'ibportstate <LID> <PORTA> reset'.",
            "3. Se a velocidade não restaurar, a falha é física: remova o cabo MPO, utilize a caneta de limpeza óptica",
            "   nas fibras e transceivers QSFP. Falhando a limpeza, substitua o cabo AOC/DAC/Fibra."
        ]
    )
    
    print_block(
        "⚠️ OUTROS ERROS CRÍTICOS", 
        general_errors, 
        [
            "Inspecione manualmente o arquivo /var/tmp/ibdiagnet2/ibdiagnet2.log para coletar o contexto exato."
        ]
    )

    print("\n" + "=" * 80 + "\n")

if __name__ == "__main__":
    analyze_ibdiagnet_log()
