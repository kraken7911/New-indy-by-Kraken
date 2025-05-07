#!/usr/bin/env python3
import hashlib
from enum import Enum, auto
from typing import Optional, List, Deque
from collections import deque
import base58
import bech32

# Константы для операций скриптов
OP_0 = 0x00
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac

# Заголовки для различных типов адресов
P2PKH_ADDRESS_HEADER = 0x00
P2SH_ADDRESS_HEADER = 0x05
BECH32_HRP = 'bc'

# Функции хеширования
sha256 = lambda bytes: hashlib.sha256(bytes).digest()
ripemd160 = lambda bytes: hashlib.new('ripemd160', bytes).digest()
hash160 = lambda bytes: ripemd160(sha256(bytes))

# Перечисление для типов скриптов
class ScriptType(Enum):
    LEGACY = auto()  # P2PKH
    COMPAT = auto()  # P2SH of P2WPKH
    SEGWIT = auto()  # P2WPKH

    def build_output_script(self, pubkey: bytes) -> bytes:
        if self is ScriptType.LEGACY:
            return _build_p2pkh_output_script(hash160(pubkey))
        if self is ScriptType.COMPAT:
            script = _build_segwit_output_script(hash160(pubkey))
            return _build_p2sh_output_script(hash160(script))
        if self is ScriptType.SEGWIT:
            return _build_segwit_output_script(hash160(pubkey))
        raise ValueError('Unrecognized address type')

    def build_input_script(self, pubkey: bytes, signature: bytes) -> bytes:
        if self is ScriptType.LEGACY:
            return _build_p2pkh_input_script(pubkey, signature)
        if self is ScriptType.COMPAT:
            script = _build_segwit_output_script(hash160(pubkey))
            return _build_p2sh_input_script(script)
        if self is ScriptType.SEGWIT:
            return bytes()
        raise ValueError('Unrecognized address type')

    def build_witness(self, pubkey: bytes, signature: bytes) -> List[bytes]:
        if self is ScriptType.LEGACY:
            return []
        if self in [ScriptType.COMPAT, ScriptType.SEGWIT]:
            return [signature, pubkey]
        raise ValueError('Unrecognized address type')

# Класс для итерации по возможным скриптам дескрипторов
class ScriptIterator:
    """
    Итератор, который может перебирать все возможные скрипты для разных дескрипторов.
    """
    def __init__(self, descriptors, master_key, address_gap: int, account_gap: int):
        self.master_key = master_key
        self.index = 0
        self.descriptors = descriptors
        self.last_descriptor = None
        self.address_gap = address_gap
        self.account_gap = account_gap

    def _next_descriptor_script(self):
        if self.last_descriptor and self.last_descriptor.has_priority_scripts():
            return self.last_descriptor.next_script(self.master_key)

        self.last_descriptor = self.descriptors[self.index]
        iter = self.last_descriptor.next_script(self.master_key)

        self.index += 1
        if self.index >= len(self.descriptors):
            self.index = 0

        return iter

    def next_script(self):
        skipped = 0
        while skipped < len(self.descriptors):
            iter = self._next_descriptor_script()
            if iter:
                return iter
            skipped += 1
        return None

    def total_scripts(self):
        return sum([d.total_scripts for d in self.descriptors])

# Функции для создания различных типов скриптов
def build_output_script_from_address(address: str) -> Optional[bytes]:
    """
    Создаем выходной скрипт для данного адреса.
    Попытка сначала декодировать Base58 адрес, затем Bech32 адрес.
    """
    # Попытка декодировать Base58 адрес
    try:
        decoded = base58.b58decode_check(address)
        version = decoded[0]
        hash = decoded[1:]

        if version == P2PKH_ADDRESS_HEADER:
            return _build_p2pkh_output_script(hash)

        if version == P2SH_ADDRESS_HEADER:
            return _build_p2sh_output_script(hash)

    except ValueError:
        pass

    # Попытка декодировать Bech32 адрес
    try:
        version, hash = bech32.decode(BECH32_HRP, address)

        if version == 0:
            return _build_segwit_output_script(hash)

    except ValueError:
        pass

    return None

# Вспомогательные функции для создания выходных скриптов (P2PKH, P2SH, SegWit)
def _build_p2pkh_output_script(pubkey_hash: bytes) -> bytes:
    script = bytearray()
    script.append(OP_DUP)
    script.append(OP_HASH160)
    script.append(len(pubkey_hash))
    script.extend(pubkey_hash)
    script.append(OP_EQUALVERIFY)
    script.append(OP_CHECKSIG)
    return bytes(script)

def _build_p2sh_output_script(script_hash: bytes) -> bytes:
    script = bytearray()
    script.append(OP_HASH160)
    script.append(len(script_hash))
    script.extend(script_hash)
    script.append(OP_EQUAL)
    return bytes(script)

def _build_segwit_output_script(hash: bytes) -> bytes:
    script = bytearray()
    script.append(OP_0)
    script.append(len(hash))
    script.extend(hash)
    return bytes(script)

# Вспомогательные функции для создания входных скриптов (P2PKH, P2SH)
def _build_p2pkh_input_script(pubkey: bytes, signature: bytes) -> bytes:
    script = bytearray()
    script.append(len(signature))
    script.extend(signature)
    script.append(len(pubkey))
    script.extend(pubkey)
    return bytes(script)

def _build_p2sh_input_script(*args: bytes) -> bytes:
    script = bytearray()
    for arg in args:
        script.append(len(arg))
        script.extend(arg)
    return bytes(script)
