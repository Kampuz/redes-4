import sys
import re

def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        print()
        sys.exit(0)

def input_to_bytes(s: str) -> bytes:
    s = s.strip()

    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]

    cleaned = re.sub(r'[\s:\-]', '', s)

    if re.fullmatch(r'[0-9a-fA-F]+', cleaned) and len(cleaned) % 2 == 0:
        return bytes.fromhex(cleaned)
    
    return s.encode('utf-8')

def format_u32_hex(v: int) -> str:
    return "0x" + format(v & 0xFFFFFFFF, "08X")


def _gen_table():
    poly = 0xEDB88320
    table = []
    
    for i in range(256):
        crc = i

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    
        table.append(crc & 0xFFFFFFFF)
    
    return table

_CRC32_TABLE = _gen_table()

def crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF

    for b in data:
        crc = (crc >> 8) ^ _CRC32_TABLE[(crc ^ b) & 0xFF]
    
    crc ^= 0xFFFFFFFF
    return crc & 0xFFFFFFFF

def parte_crc():
    print("Entrada de dados (texto ASCII ou hexadecimal)")
    data_str = ask("Dados -> ")
    data_bytes = input_to_bytes(data_str)

    crc = crc32(data_bytes)
    fcs = (~crc) & 0xFFFFFFFF

    print("\n--- Resultado ---")
    print(f"Bytes ({len(data_bytes)}): {data_bytes.hex().upper()}")
    print(f"CRC-32 calculado: {format_u32_hex(crc)}")
    print(f"FCS (complemento de 1 do CRC): {format_u32_hex(fcs)}")

    return fcs

def parte_fcs(fcs):
    recv = ask("\nDigite o FCS recebido ou ENTER para pular: ").strip()

    if recv == "":
        return
    
    try:
        if recv.startswith("0x") or recv.startswith("0X"):
            recv_val = int(recv, 16)
        else:
            if re.fullmatch(r'[0-9a-fA-F]{1,8}', recv):
                recv_val = int(recv_val, 16)
            else:
                recv_val = int(recv, 10)
    except ValueError:
        print("Formato de FCS inválido. Use hex ou decimal.")
        return
    
    recv_val &= 0xFFFFFFFF
    print(f"FCS recebido interpretado como: {format_u32_hex(recv_val)}")

    if recv_val == fcs:
        print("Resultado da validação: QUADRO CORRETO (FCS corresponde).")
    else:
        print("Resultado da validação: QUADRO CORROMPIDO (FCS diferente).")

    print(f"FCS esperado: {format_u32_hex(fcs)} (diferença: 0x{(recv_val ^ fcs):08X})")


def main():

    fcs = parte_crc()

    parte_fcs(fcs)



if __name__ == "__main__":
    main()