from typing import List
from bip32 import BIP32
import scanner
import scripts
import coincurve

NON_SEGWIT_DUST = 546  # обычно 546 сатоши для P2PKH
SIGHASH_ALL = 0x01

class Transaction:
    """
    Sweep transaction.
    """

    def __init__(self, master_key: BIP32, utxos: List[scanner.Utxo], addresses: List[str], total_amount_in_sat: int):
        """
        Craft and sign a transaction that spends all the UTXOs and sends the requested funds to multiple addresses.
        """
        if len(addresses) > 40:
            raise ValueError('Too many addresses. Maximum is 40.')

        self.outputs = []
        amount_per_address = total_amount_in_sat // len(addresses)
        
        if amount_per_address < NON_SEGWIT_DUST:
            raise ValueError('Not enough funds to create transactions for all addresses.')

        for address in addresses:
            output_script = scripts.build_output_script_from_address(address)
            if output_script is None:
                raise ValueError(f'The address {address} is invalid or the format isn\'t recognized.')
            self.outputs.append((amount_per_address, output_script))

        self.inputs = []
        for utxo in utxos:
            pubkey = master_key.get_pubkey_from_path(utxo.path.to_list())
            privkey = master_key.get_privkey_from_path(utxo.path.to_list())

            # Для LEGACY-адресов формируем скрипт вывода по публичному ключу
            if utxo.script_type == scripts.ScriptType.LEGACY:
                script = scripts.ScriptType.LEGACY.build_output_script(pubkey)
            else:
                script = utxo.script_type.build_output_script(pubkey)

            # Подпись: double sha256 от скрипта
            sighash = scripts.sha256(scripts.sha256(bytes(script)))
            signature = coincurve.PrivateKey(privkey).sign(sighash, hasher=None)
            extended_signature = bytearray(signature)
            extended_signature.append(SIGHASH_ALL)

            # Формируем скрипты для входа и (опционально) witness
            input_script = utxo.script_type.build_input_script(pubkey, extended_signature)
            witness = utxo.script_type.build_witness(pubkey, extended_signature)

            self.inputs.append((utxo, input_script, witness))