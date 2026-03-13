import hashlib
import re
import sys
import getpass
import urllib.request
import urllib.error

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "PasswordAuditLinkedIn/1.0 (educational script)"

COMMON_PATTERNS = [
    r"password", r"123456", r"qwerty", r"admin", r"letmein", r"iloveyou"
]

def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()

def hibp_pwned_count(password: str, timeout: int = 10) -> int:
    """
    Checks if a password appears in known breaches using HIBP k-anonymity.
    Sends only first 5 chars of SHA1 hash to the API.
    Returns the number of times it was seen, or 0 if not found.
    """
    full_hash = sha1_hex(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    req = urllib.request.Request(
        HIBP_RANGE_URL.format(prefix),
        headers={"User-Agent": USER_AGENT}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HIBP HTTP error: {e.code}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"HIBP connection error: {e.reason}") from e

    # Response lines look like: <HASH_SUFFIX>:<COUNT>
    for line in body.splitlines():
        if ":" not in line:
            continue
        h_suf, count = line.split(":", 1)
        if h_suf.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0

def score_password(pw: str) -> tuple[int, list[str]]:
    """
    Simple scoring model (0-100) + feedback.
    """
    feedback = []
    score = 0

    length = len(pw)
    if length >= 14:
        score += 35
    elif length >= 10:
        score += 25
    elif length >= 8:
        score += 15
        feedback.append("Considere aumentar para 10+ caracteres.")
    else:
        score += 5
        feedback.append("Senha curta: prefira 10–14+ caracteres.")

    # Character classes
    classes = 0
    if re.search(r"[a-z]", pw):
        classes += 1
    else:
        feedback.append("Falta letra minúscula (a-z).")
    if re.search(r"[A-Z]", pw):
        classes += 1
    else:
        feedback.append("Falta letra maiúscula (A-Z).")
    if re.search(r"\d", pw):
        classes += 1
    else:
        feedback.append("Falta número (0-9).")
    if re.search(r"[^A-Za-z0-9]", pw):
        classes += 1
    else:
        feedback.append("Falta símbolo (ex: !@#$%).")

    score += classes * 10  # up to 40

    # Penalties for common patterns
    lowered = pw.lower()
    for pat in COMMON_PATTERNS:
        if re.search(pat, lowered):
            score -= 20
            feedback.append("Contém padrão comum (ex: password/123456/qwerty).")
            break

    # Repeated chars / sequences
    if re.search(r"(.)\1\1", pw):
        score -= 10
        feedback.append("Muitos caracteres repetidos (ex: aaa/111).")
    if re.search(r"0123|1234|2345|3456|4567|5678|6789", pw):
        score -= 10
        feedback.append("Sequência numérica detectada (ex: 1234).")
    if re.search(r"abcd|bcde|cdef|defg|efgh|fghi|ghij", lowered):
        score -= 10
        feedback.append("Sequência de letras detectada (ex: abcd).")

    # Clamp
    score = max(0, min(100, score))
    if score >= 80:
        feedback.insert(0, "Boa! Parece uma senha forte.")
    elif score >= 60:
        feedback.insert(0, "Razoável, mas dá pra reforçar.")
    else:
        feedback.insert(0, "Fraca: vale melhorar antes de usar.")

    return score, feedback

def risk_label(score: int, pwned_count: int | None) -> str:
    if pwned_count is not None and pwned_count > 0:
        return "CRÍTICO (apareceu em vazamentos)"
    if score >= 80:
        return "BAIXO"
    if score >= 60:
        return "MÉDIO"
    return "ALTO"

def main() -> int:
    print("=== Password Audit (educacional) ===")
    print("Dica: sua senha NÃO será exibida. Checagem HIBP usa k-anonymity.\n")

    pw = getpass.getpass("Digite uma senha para analisar: ").strip()
    if not pw:
        print("Nenhuma senha informada.")
        return 1

    score, feedback = score_password(pw)

    # Ask if user wants HIBP check (nice for LinkedIn to show privacy awareness)
    choice = input("\nChecar se apareceu em vazamentos (HIBP)? [S/n] ").strip().lower()
    do_hibp = (choice != "n")

    pwned = None
    if do_hibp:
        try:
            pwned = hibp_pwned_count(pw)
        except RuntimeError as e:
            print(f"\n[!] Não foi possível checar HIBP: {e}")
            print("    (Você ainda tem a avaliação local de força.)")

    print("\n--- Resultado ---")
    print(f"Score: {score}/100")
    if pwned is not None:
        if pwned > 0:
            print(f"Vazamentos: ENCONTRADA ({pwned} vezes)")
        else:
            print("Vazamentos: não encontrada (na base do HIBP)")
    print(f"Risco: {risk_label(score, pwned)}\n")

    print("Sugestões:")
    for item in feedback:
        print(f" - {item}")

    print("\nBoas práticas rápidas:")
    print(" - Use frases longas (passphrases) + variedade de caracteres.")
    print(" - Evite reutilizar senhas entre serviços.")
    print(" - Use um gerenciador de senhas e ative MFA onde der.\n")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())