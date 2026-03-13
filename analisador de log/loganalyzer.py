import re
from collections import Counter
from pathlib import Path

# 1) Regex: identifica linhas de falha e extrai o IP
FAILED_REGEX = re.compile(
    r"Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def analyze_ssh_failed_logins(log_path: str, threshold: int = 5) -> tuple[Counter, dict]:
    """
    Lê o arquivo de log e conta tentativas falhas por IP.
    - log_path: caminho do arquivo de log
    - threshold: limite mínimo para marcar como suspeito
    Retorna:
      - counts: Counter com quantidade de falhas por IP
      - suspects: dict {ip: contagem} apenas com IPs >= threshold
    """
    counts = Counter()

    # 2) Abre o arquivo de log (ignorando caracteres estranhos)
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # 3) Procura padrão de "Failed password..."
            match = FAILED_REGEX.search(line)

            # 4) Se encontrou, pega o IP e incrementa contador
            if match:
                ip = match.group("ip")
                counts[ip] += 1

    # 5) Filtra apenas IPs que passaram do limite (suspeitos)
    suspects = {ip: c for ip, c in counts.items() if c >= threshold}

    return counts, suspects

def print_report(counts: Counter, suspects: dict, top_n: int = 10) -> None:
    """
    Mostra um relatório no terminal.
    - top_n: quantos IPs mostrar no ranking
    """
    print("\n--- TOP IPs com falha ---")
    if not counts:
        print("Nenhuma tentativa falha encontrada.")
        return

    for ip, c in counts.most_common(top_n):
        print(f"{ip:<15}  ->  {c} falhas")

    print("\n--- ALERTAS (suspeitos) ---")
    if not suspects:
        print("Nenhum IP passou do limite definido.")
    else:
        for ip, c in sorted(suspects.items(), key=lambda x: x[1], reverse=True):
            print(f"[ALERTA] {ip}  ->  {c} falhas (possível brute force)")

def main() -> int:
    print("=== SSH Brute Force Log Analyzer (educacional) ===")

    # 6) Entrada do usuário: caminho do log
    log_path = input("Caminho do log (ex: /var/log/auth.log): ").strip()

    # 7) Verifica se o arquivo existe (boa prática)
    if not Path(log_path).is_file():
        print("Arquivo não encontrado. Verifique o caminho e tente de novo.")
        return 1

    # 8) Entrada do usuário: threshold
    threshold_raw = input("Limite de falhas para alertar (padrão=5): ").strip()
    threshold = int(threshold_raw) if threshold_raw.isdigit() else 5

    # 9) Análise
    counts, suspects = analyze_ssh_failed_logins(log_path, threshold)

    # 10) Relatório
    print_report(counts, suspects, top_n=10)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())