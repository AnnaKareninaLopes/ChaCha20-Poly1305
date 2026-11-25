from cripto import cifrar, decifrar, montar_nonce, ID_A, ID_B, gerar_salt, derivar_chave

# Dicionário que liga a letra do remetente ao número usado no nonce.
IDS = {b"A": ID_A, b"B": ID_B}


def montar_pacote(chave: bytes, remetente: bytes, contador: int, mensagem: str) -> bytes:
    nonce = montar_nonce(IDS[remetente], contador)
    cifrado = cifrar(chave, nonce, mensagem, remetente) # remetente = AAD
    corpo = remetente + nonce + cifrado # O + entre bytes cola um atrás do outro
    tamanho = len(corpo).to_bytes(4, "big") # transforma um número em 4 bytes
    return tamanho + corpo


def desmontar_pacote(chave: bytes, corpo: bytes) -> tuple:
    remetente = corpo[0:1]
    nonce = corpo[1:13]
    cifrado = corpo[13:]
    contador = int.from_bytes(nonce[4:12], "big")
    # int.from_bytes(..., "big") faz o contrário do to_bytes: transforma bytes
    # de volta em número
    mensagem = decifrar(chave, nonce, cifrado, remetente)
    return remetente, contador, mensagem


if __name__ == '__main__':
    chave = derivar_chave("senha12", gerar_salt())
    pacote = montar_pacote(chave, b"A", 0, "oi")
    print("pacote:", len(pacote), "bytes")
    print("tamanho:    ", pacote[0:4].hex())
    print("remetente:  ", pacote[4:5])
    print("nonce:      ", pacote[5:17].hex())
    print("cifrado+tag:", pacote[17:].hex())

    print()
    # Simulando quem recebe:
    tamanho = int.from_bytes(pacote[0:4], "big")
    corpo = pacote[4:4 + tamanho]
    print("tamanho lido:", tamanho)
    remetente, contador, mensagem = desmontar_pacote(chave, corpo)
    print("remetente:", remetente, "| contador:", contador, "| mensagem:", mensagem)
    print(corpo[0], "|", corpo[0:1])

    # bytes é uma fila de números, então:
    # corpo[0] pega um item da fila, e cada item é um número. A letra "A" é
    # guardada como o número 65. Essa é a tabela ASCII, em que cada letra tem
    # um número.
    # corpo[0:1] é uma fatia, e uma fatia de bytes continua sendo bytes: b'A',
    # uma fila com 1 item só.

    # Regra: [posição] devolve um número; [início:fim] devolve bytes.