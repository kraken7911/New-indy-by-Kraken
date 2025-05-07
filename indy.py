import argparse
import asyncio
import json
import random
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from threading import Lock

from bip32 import BIP32
from connectrum.svr_info import ServerInfo
from connectrum.client import StratumClient
from mnemonic import Mnemonic

import scanner
import transactions

def parse_key(key: str, passphrase: str) -> BIP32:
    try:
        private_key = BIP32.from_xpriv(key)
        return private_key
    except Exception:
        pass
    try:
        public_key = BIP32.from_xpub(key)
        return public_key
    except Exception:
        pass
    try:
        language = Mnemonic.detect_language(key)
        seed = Mnemonic(language).to_seed(key, passphrase=passphrase)
        private_key = BIP32.from_seed(seed)
        return private_key
    except Exception:
        pass
    raise ValueError('The key is invalid or the format isn\'t recognized. Make sure it\'s a mnemonic, xpriv or xpub.')

async def find_utxos(
        server: ServerInfo,
        master_key: BIP32,
        address_gap: int,
        account_gap: int,
        should_batch: bool
):
    client = StratumClient()
    await client.connect(server, disable_cert_verify=True)
    utxos = await scanner.scan_master_key(client, master_key, address_gap, account_gap, should_batch)
    balance = sum([utxo.amount_in_sat for utxo in utxos])
    client.close()
    return utxos, balance

def process_wallet(mnemonic: str, args, server: ServerInfo, pos_path, zero_path, pos_lock, zero_lock):
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    try:
        master_key = parse_key(mnemonic, args.passphrase)
        utxos, balance = loop.run_until_complete(
            find_utxos(
                server,
                master_key,
                args.address_gap,
                args.account_gap,
                should_batch=not args.no_batching
            )
        )
        addresses = list({getattr(utxo, "address", None) for utxo in utxos if getattr(utxo, "address", None)}) if utxos else []
        result = f"Mnemonic: {mnemonic}\n"
        if addresses:
            result += "\n".join([f"Address: {addr}" for addr in addresses]) + "\n"
        else:
            result += "Address: (not found)\n"
        result += f"Balance: {balance} sats\n"
        result += f"UTXOs: {utxos}\n"
    except Exception as e:
        result = f"Mnemonic: {mnemonic}\nError: {str(e)}\n"
        balance = 0

    # Сохраняем результат сразу в файл (thread-safe)
    if balance > 0:
        with pos_lock:
            with open(pos_path, 'a', encoding='utf-8') as f:
                f.write(result + "\n" + ("-"*30) + "\n")
    else:
        with zero_lock:
            with open(zero_path, 'a', encoding='utf-8') as f:
                f.write(result + "\n" + ("-"*30) + "\n")
    return balance  # возвращаем только для совместимости, не обязательно

def create_empty_results_files(pos_path, zero_path):
    # Создание/очистка файлов при запуске
    with open(pos_path, 'w', encoding='utf-8') as f:
        f.write("")
    with open(zero_path, 'w', encoding='utf-8') as f:
        f.write("")

def main():
    print("Текущая рабочая папка:", os.getcwd())
    parser = argparse.ArgumentParser(
        description='Find and sweep all the funds from mnemonics or bitcoin keys, regardless of derivation path or address format used.'
    )

    parser.add_argument('file', help='Path to a file containing mnemonics (one per line)')
    parser.add_argument('--passphrase', metavar='<pass>', default='',
                        help='Optional secret phrase necessary to decode the mnemonics')
    parser.add_argument('--output', metavar='<output_file>', default='results',
                        help='Prefix for result files (default: results)')

    scanning = parser.add_argument_group('scanning parameters')
    scanning.add_argument('--address-gap', metavar='<num>', default=20, type=int,
                          help='Max empty addresses gap to explore (default: 20)')
    scanning.add_argument('--account-gap', metavar='<num>', default=0, type=int,
                          help='Max empty account levels gap to explore (default: 0)')

    electrum = parser.add_argument_group('electrum server')
    electrum.add_argument('--host', metavar='<host>',
                          help='Hostname of the electrum server to use')
    electrum.add_argument('--port', metavar='<port>', type=int,
                          help='Port number of the electrum server to use')
    electrum.add_argument('--protocol', choices='ts', default='s',
                          help='Electrum connection protocol: t=TCP, s=SSL (default: s)')
    electrum.add_argument('--no-batching', default=False, action='store_true',
                          help='Disable request batching')

    args = parser.parse_args()

    # Read mnemonics from file
    with open(args.file, 'r', encoding='utf-8') as f:
        mnemonics = [line.strip() for line in f.readlines() if line.strip()]

    # Выбор сервера
    if args.host is not None:
        port = (args.protocol + str(args.port)) if args.port else args.protocol
        server = ServerInfo(args.host, hostname=args.host, ports=port)
    else:
        with open('servers.json', 'r', encoding='utf-8') as f:
            servers = json.load(f)
        srv = random.choice(servers)
        server = ServerInfo(srv['host'], hostname=srv['host'], ports=srv['port'])

    # Формируем абсолютные пути для сохранения (относительно рабочей директории)
    cwd = os.getcwd()
    pos_path = os.path.join(cwd, f"{args.output}_positive.txt")
    zero_path = os.path.join(cwd, f"{args.output}_zero.txt")

    # Создаем/очищаем файлы в самом начале работы
    create_empty_results_files(pos_path, zero_path)

    print("Сохраняю positive результаты в:", pos_path)
    print("Сохраняю zero результаты в:", zero_path)

    # Locks для потокобезопасной записи
    pos_lock = Lock()
    zero_lock = Lock()

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [
            executor.submit(process_wallet, mnemonic, args, server, pos_path, zero_path, pos_lock, zero_lock)
            for mnemonic in mnemonics
        ]
        # Можно отслеживать прогресс, если нужно:
        for i, f in enumerate(as_completed(futures), 1):
            f.result()
            print(f"Обработано {i} из {len(mnemonics)}")

    print(f"Готово! Positive balances в {pos_path}, zero balances в {zero_path}")

if __name__ == '__main__':
    main()