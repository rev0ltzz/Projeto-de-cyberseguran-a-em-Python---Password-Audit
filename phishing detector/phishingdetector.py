from urllib.parse import urlparse
import re
import ipaddress


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "password", "confirm", "signin", "security", "webscr", "paypal",
    "alert", "unlock", "suspended", "validate", "credential"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "cutt.ly", "rb.gy"
]


def normalize_url(url: str) -> str:
    """Adiciona http:// caso a URL venha sem esquema."""
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


def is_ip_address(domain: str) -> bool:
    """Verifica se o domínio é um endereço IP."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def count_subdomains(domain: str) -> int:
    """
    Conta quantos níveis existem antes do domínio principal.
    Ex.: a.b.example.com -> 2 subdomínios (a, b)
    """
    parts = domain.split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def contains_suspicious_keywords(url: str) -> list:
    """Retorna palavras suspeitas encontradas na URL."""
    found = []
    lower_url = url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_url:
            found.append(keyword)
    return found


def analyze_url(url: str) -> dict:
    """
    Analisa uma URL e retorna pontuação, classificação e motivos.
    """
    score = 0
    reasons = []

    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Remove porta caso exista
    if ":" in domain:
        domain = domain.split(":")[0]

    # 1) Domínio em formato IP
    if is_ip_address(domain):
        score += 30
        reasons.append("A URL usa endereço IP em vez de domínio.")

    # 2) Uso de @
    if "@" in normalized:
        score += 20
        reasons.append("A URL contém '@', técnica usada para confundir o usuário.")

    # 3) Domínio muito longo
    if len(domain) > 30:
        score += 10
        reasons.append("O domínio é muito longo.")

    # 4) Muitos subdomínios
    subdomain_count = count_subdomains(domain)
    if subdomain_count >= 3:
        score += 15
        reasons.append(f"A URL possui muitos subdomínios ({subdomain_count}).")

    # 5) Excesso de hífens
    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        score += 10
        reasons.append(f"O domínio contém muitos hífens ({hyphen_count}).")

    # 6) Encurtador de URL
    if domain in SHORTENERS:
        score += 25
        reasons.append("A URL usa um encurtador, o que pode ocultar o destino real.")

    # 7) Palavras suspeitas
    suspicious_words = contains_suspicious_keywords(normalized)
    if suspicious_words:
        added_score = min(len(suspicious_words) * 5, 20)
        score += added_score
        reasons.append(
            f"Foram encontradas palavras suspeitas: {', '.join(suspicious_words)}."
        )

    # 8) Muitas barras no caminho
    slash_count = path.count("/")
    if slash_count >= 5:
        score += 10
        reasons.append("A URL possui estrutura de caminho excessivamente longa.")

    # 9) HTTPS ausente
    if parsed.scheme != "https":
        score += 10
        reasons.append("A URL não usa HTTPS.")

    # 10) Números em excesso no domínio
    digit_count = sum(c.isdigit() for c in domain)
    if digit_count >= 5:
        score += 10
        reasons.append("O domínio contém muitos números, o que pode ser suspeito.")

    # Classificação final
    if score >= 60:
        risk = "ALTO"
    elif score >= 30:
        risk = "MÉDIO"
    else:
        risk = "BAIXO"

    return {
        "url": url,
        "normalized_url": normalized,
        "domain": domain,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }


def print_report(result: dict) -> None:
    """Exibe o relatório de análise da URL."""
    print("\n" + "=" * 60)
    print("RELATÓRIO DE ANÁLISE DE PHISHING")
    print("=" * 60)
    print(f"URL analisada : {result['url']}")
    print(f"Domínio       : {result['domain']}")
    print(f"Pontuação     : {result['score']}")
    print(f"Nível de risco: {result['risk']}")
    print("-" * 60)

    if result["reasons"]:
        print("Motivos do alerta:")
        for i, reason in enumerate(result["reasons"], start=1):
            print(f"{i}. {reason}")
    else:
        print("Nenhum indício forte de phishing foi encontrado.")
    print("=" * 60)


def main():
    print("Detector simples de URLs suspeitas de phishing")
    url = input("Digite a URL para análise: ").strip()

    result = analyze_url(url)
    print_report(result)


if __name__ == "__main__":
    main()