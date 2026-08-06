#!/usr/bin/env python3
"""
Leitor Humano de Relatórios ibdiagnet (RHEL 8 / Mellanox)
Filtra o log denso gerado pelo ibdiagnet, identifica o Master Subnet Manager
e exibe apenas os erros críticos que exigem intervenção.
"""

import os
import sys

# Caminho padrão onde o ibdiagnet salva o log principal
LOG_FILE = "/var/tmp/ibdiagnet2/ibdiagnet2.log"

def analyze_ibdiagnet_log():
    if not os.path.exists(LOG_FILE):
        print(f"ERRO | Arquivo não encontrado: {LOG_FILE}")
        print("DICA | Execute o comando 'ibdiagnet' como root para gerar o relatório atualizado antes de rodar este script.")
        sys.exit(1)

    # Armazena os erros encontrados
    duplications = set()
    routing = set()
    downgrades = set()
    general_errors = set()
    
    # Variável para armazenar quem é o switch principal (SM)
    master_sm_info = "Não localizado no log (O Subnet Manager pode estar inativo ou o log está incompleto!)"

    print(f"Lendo relatório da fabric gerado em: {LOG_FILE}")
    print("=" * 80)

    # Leitura e parsing do arquivo
    with open(LOG_FILE, 'r') as file:
        for line in file:
            line = line.strip()
            
            # 1. Identificar o Master Subnet Manager (Linhas de Informação -I-)
            if "-I-" in line and "Master SM" in line:
                # Extrai apenas a informação limpa sobre o SM
                master_sm_info = line.split("-I-", 1)[-1].strip()

            # 2. Filtragem de Erros (-E-) e Alertas (-W-)
            is_error = "-E-" in line
            is_warning = "-W-" in line

            if is_error or is_warning:
                # Limpa a linha mantendo apenas a mensagem real
                if is_error:
                    clean_line = line.split("-E-", 1)[-1].strip()
                else:
                    clean_line = line.split("-W-", 1)[-1].strip()
                
                lower_line = clean_line.lower()

                # Categorização baseada em palavras-chave vitais do InfiniBand
                if "duplicate" in lower_line or "dup " in lower_line:
                    duplications.add(clean_line)
                
                elif "routing" in lower_line or "unreach" in lower_line:
                    routing.add(clean_line)
                
                elif "downgrade" in lower_line:
                    downgrades.add(clean_line)
                
                elif is_error:
                    general_errors.add(clean_line)

    # Exibição do Master SM no topo do relatório
    print("👑 GERÊNCIA DA REDE (SUBNET MANAGER):")
    print(f"  -> {master_sm_info}")
    print("-" * 80)

    # Função auxiliar para imprimir os blocos de erro
    def print_block(title, items):
        if items:
            print(f"\n{title}")
            items_list = list(items)
            for item in items_list[:10]:
                print(f"  -> {item}")
            if len(items_list) > 10:
                print(f"  ... e mais {len(items_list) - 10} ocorrências similares (Ver log completo).")
            return True
        return False

    # Exibição Estruturada dos Erros
    has_issues = False
    
    if print_block("🚨 [CRÍTICO] Duplicações de Identificadores (GUID/LID):", duplications):
        has_issues = True
        
    if print_block("🚨 [CRÍTICO] Falhas de Roteamento / Nós Inalcançáveis:", routing):
        has_issues = True
        
    if print_block("⚠️  [ALERTA] Degradação Física (Cabos operando abaixo da velocidade):", downgrades):
        has_issues = True
        
    if print_block("⚠️  [ALERTA] Outros Erros Críticos Identificados:", general_errors):
        has_issues = True

    # Feedback Positivo se a rede estiver limpa
    if not has_issues:
        print("\nSUCCESS | HEALTH_CHECK | A malha InfiniBand está saudável!")
        print("Nenhum erro de roteamento, duplicação de GUID/LID ou degradação física encontrado.")

    print("\n" + "=" * 80)

if __name__ == "__main__":
    analyze_ibdiagnet_log()
