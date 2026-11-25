import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
# kdf (key derivation function)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

TAMANHO_SALT = 16
ID_A = 1
ID_B = 2

def gerar_salt() -> bytes:
    # Sorteia 16 bytes aleatórios para servir de salt.
    # O salt não é secreto, mas precisa ser novo a cada conexão,
    # para que a mesma senha gere uma chave diferente em cada sessão.
    return os.urandom(TAMANHO_SALT)

def derivar_chave(senha: str, salt: bytes) -> bytes:
    # Transforma a senha (texto) em uma chave de 32 bytes para o ChaCha20.
    # O scrypt é lento e gasta memória de propósito: atrapalha quem
    # tenta adivinhar a senha testando milhões de palavras.
    kdf = Scrypt(
        salt=salt,
        length=32, # 32 bytes = 256 bits, o tamanho da chave do ChaCha20.
        n=2**14,   # custo: quanto maior mais lento e mais memória.
        r=8,       # tamanho do bloco interno (influencia a memória)
        p=1        # quantas vezes o cálculo roda em paralelo
    )

    return kdf.derive(senha.encode("utf-8"))
    # senha.encode("utf-8"): converte o texto em bytes
    # kdf.derive: faz o cálculo e retorna uma chave de 32 bytes


def montar_nonce(id_remetente: int, contador: int) -> bytes:
    # Nonce de 12 bytes = 4 bytes de quem enviou + 8 bytes do contador.
    # O id impede que A e B usem o mesmo nonce (os dois começam no contador 0).
    # O contador sobe a cada mensagem, então o nonce nunca se repete na conexão.
    parte_id = id_remetente.to_bytes(4, "big")
    parte_contador = contador.to_bytes(8, "big")

    return parte_id + parte_contador

def cifrar(chave: bytes, nonce: bytes, mensagem: str, aad: bytes) -> bytes:
    chacha = ChaCha20Poly1305(chave)
    return chacha.encrypt(nonce, mensagem.encode("utf-8"), aad)
# ChaCha20Poly1305(chave) cria o "objeto cifrador" com a chave de 32 bytes que
# veio do derivar_chave.
# mensagem.encode("utf-8") transforma o texto em bytes, igual ao que foi feito
# com a senha.
# encrypt(nonce, ..., aad) faz duas coisas:
  # cifra a mensagem com o ChaCha20;
  # calcula a tag com o Poly1305, usando o cifrado e o AAD.


def decifrar(chave: bytes, nonce: bytes, cifrado: bytes, aad: bytes) -> str:
    chacha = ChaCha20Poly1305(chave)
    return chacha.decrypt(nonce, cifrado, aad).decode("utf-8")
# decrypt(nonce, cifrado, aad) faz o caminho contrário, nesta ordem:
  # primeiro recalcula a tag e compara com a que veio;
  # se for diferente, para tudo e lança o erro InvalidTag, sem devolver a mensagem;
  # se for igual, decifra.
# .decode("utf-8") transforma os bytes de volta em texto.

# Importante: o AAD entra no cálculo da tag, mas não é cifrado e não fica dentro
# do resultado. Por isso ele precisa ir separado no pacote.

if __name__ == '__main__':
    salt = gerar_salt()
    print("salt: ", salt.hex())

    chave1 = derivar_chave("senha12", salt)
    chave2 = derivar_chave("senha12", salt)
    chave3 = derivar_chave("senha13", salt)

    print("chave1: ", chave1.hex())
    print("chave2: ", chave2.hex())
    print("chave3: ", chave3.hex())

    print("tamanho: ", len(chave1), "bytes")

    print()
    print("nonce A,0:", montar_nonce(ID_A, 0).hex())
    print("nonce B,0:", montar_nonce(ID_B, 0).hex())
    print("nonce A,1:", montar_nonce(ID_A, 1).hex())
    print("tamanho:", len(montar_nonce(ID_A, 0)), "bytes")

    print()
    nonce = montar_nonce(ID_A, 0)
    cifrado = cifrar(chave1, nonce, "oi", b"A")
    print("mensagem: 2 bytes")
    print("cifrado + tag:", len(cifrado), "bytes ->", cifrado.hex())
    print("decifrado:", decifrar(chave1, nonce, cifrado, b"A"))

    print()
    # Teste 1: AAD trocado (alguém mudou o remetente de A para B)
    try:
        decifrar(chave1, nonce, cifrado, b"B")
    except InvalidTag:
        print("AAD trocado: InvalidTag, mensagem recusada")

    # Teste 2: 1 byte do cifrado alterado
    adulterado = bytearray(cifrado)
    # bytearray(cifrado): em Python, um valor do tipo bytes não pode ser alterado.
    # O bytearray é uma cópia que pode.
    adulterado[0] = adulterado[0] ^ 1
    # adulterado[0] ^ 1: o ^ é o XOR. Fazer XOR com 1 inverte o último bit do
    # primeiro byte (0 vira 1, 1 vira 0). É a menor alteração possível: 1 bit.
    print("original:  ", cifrado.hex())
    print("adulterado:", bytes(adulterado).hex())
    # bytes(adulterado): converte de volta para bytes, que é o tipo que o
    # decrypt espera.
    try:
        decifrar(chave1, nonce, bytes(adulterado), b"A")
    except InvalidTag:
        print("1 byte alterado: InvalidTag, mensagem recusada")


# Sorteia salt, passa salt e chave pro derivar_chave, scrypt calcula a chave.
# scrypt é a função, chave é o resultado, ela que muda, não o scrypt.
