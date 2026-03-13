import re
import ipaddress
from hashlib import md5, sha1, sha256


MALICIOUS_IPS = {
    "185.220.101.1": "IP associado a atividade maliciosa simulada",
    "45.77.88.99": "IP suspeito de comunicação C2",
    "103.21.244.10": "IP listado em base local de IOC"
}

MALICIOUS_DOMAINS = {
    "secure-login-update.com": "Domínio suspeito de phishing",
    "free-prize-alert.net": "Domínio relacionado a campanha fraudulenta",
    "malware-download.org": "Domínio associado a entrega de malware"
}

MALICIOUS_HASHES = {
    "5d41402abc4b2a76b9719d911017c592": "Hash MD5 listado como arquivo malicioso",
    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": "Hash SHA1 suspeito",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": "Hash SHA256 associado a malware"
}


def detect_ioc_type(ioc: str) -> str:
    """Identifica se o IOC é IP, domínio, hash ou desconhecido."""
    ioc = ioc.strip()

    # Verifica IP
    try:
        ipaddress.ip_address(ioc)
        return "IP"
    except ValueError:
        pass

    # Verifica hash MD5
    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "MD5"

    # Verifica hash SHA1
    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "SHA1"

    # Verifica hash SHA256
    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "SHA256"

    # Verifica domínio
    if re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+", ioc):
        return "DOMAIN"

    return "UNKNOWN"


def check_local_database(ioc: str, ioc_type: str) -> dict:
    """Consulta a base local simulada de IOCs."""
    ioc_lower = ioc.lower()

    if ioc_type == "IP":
        if ioc in MALICIOUS_IPS:
            return {"status": "MALICIOUS", "details": MALICIOUS_IPS[ioc]}
        return {"status": "NOT FOUND", "details": "IP não encontrado na base local."}

    if ioc_type == "DOMAIN":
        if ioc_lower in MALICIOUS_DOMAINS:
            return {"status": "MALICIOUS", "details": MALICIOUS_DOMAINS[ioc_lower]}
        return {"status": "NOT FOUND", "details": "Domínio não encontrado na base local."}

    if ioc_type in ["MD5", "SHA1", "SHA256"]:
        if ioc_lower in MALICIOUS_HASHES:
            return {"status": "MALICIOUS", "details": MALICIOUS_HASHES[ioc_lower]}
        return {"status": "NOT FOUND", "details": "Hash não encontrado na base local."}

    return {"status": "INVALID", "details": "Tipo de IOC não reconhecido."}


def analyze_ioc(ioc: str) -> dict:
    """Analisa o IOC e gera um relatório estruturado."""
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "UNKNOWN":
        return {
            "ioc": ioc,
            "type": "UNKNOWN",
            "status": "INVALID",
            "risk": "ALTO",
            "details": "O valor informado não corresponde a um IP, domínio ou hash válido."
        }

    db_result = check_local_database(ioc, ioc_type)

    if db_result["status"] == "MALICIOUS":
        risk = "ALTO"
    elif db_result["status"] == "NOT FOUND":
        risk = "BAIXO"
    else:
        risk = "MÉDIO"

    return {
        "ioc": ioc,
        "type": ioc_type,
        "status": db_result["status"],
        "risk": risk,
        "details": db_result["details"]
    }


def print_report(result: dict) -> None:
    """Exibe o relatório final."""
    print("\n" + "=" * 60)
    print("RELATÓRIO DE IOC SCANNER")
    print("=" * 60)
    print(f"IOC analisado  : {result['ioc']}")
    print(f"Tipo detectado : {result['type']}")
    print(f"Status         : {result['status']}")
    print(f"Nível de risco : {result['risk']}")
    print(f"Detalhes       : {result['details']}")
    print("=" * 60)


def main():
    print("IOC Scanner Automático")
    ioc = input("Digite um IP, domínio ou hash para análise: ").strip()

    result = analyze_ioc(ioc)
    print_report(result)


if __name__ == "__main__":
    main()