import random
import asyncio
import hashlib
import dataclasses
from loguru import logger
from starknet_py.hash.address import compute_address
from starknet_py.net.account.account import Account
from starknet_py.net.client import Client
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.models import StarknetChainId
from starknet_py.net.networks import MAINNET
from starknet_py.net.signer.stark_curve_signer import KeyPair
from starknet_py.hash.utils import message_signature, compute_hash_on_elements
from starknet_py.net.models import AddressRepresentation, StarknetChainId, parse_address
from starknet_py.net.account.account_deployment_result import AccountDeploymentResult
from starknet_py.net.account.account import _add_max_fee_to_transaction
from starknet_py.net.signer import BaseSigner
from starknet_py.net.models.transaction import (
    AccountTransaction,
    Declare,
    DeclareV2,
    
    DeployAccount,
    Invoke,
)
from typing import List, Optional, cast
from starknet_py.constants import DEFAULT_ENTRY_POINT_SELECTOR
from starknet_py.hash.transaction import (
    TransactionHashPrefix,
    compute_declare_transaction_hash,
    compute_declare_v2_transaction_hash,
    compute_deploy_account_transaction_hash,
    compute_transaction_hash,
)
from config import *
from starknet_py.net.client_models import EstimatedFee
from starknet_py.net.account.account import _add_max_fee_to_transaction, _add_signature_to_transaction
from starknet_py.hash.utils import compute_hash_on_elements

chain = StarknetChainId.MAINNET

ACTUAL_IMPL = 0x2c2b8f559e1221468140ad7b2352b1a5be32660d0bf1a3ae3a054a4ec5254e4

async def sleeping(address, error = False):
    if error:
        rand_time = random.randint(ErrorSleepeng[0], ErrorSleepeng[1])
    else:
        rand_time = random.randint(TaskSleep[0], TaskSleep[1])
    logger.info(f'[{address}] sleeping {rand_time} s')
    await asyncio.sleep(rand_time)

def get_random_value_int(param):
    return random.randint(param[0], param[1])

def import_stark_account(private_key: int, client):
    if provider == "argent":
        class_hash = 0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918

        key_pair = KeyPair.from_private_key(private_key)
        salt = key_pair.public_key


        account_initialize_call_data = [key_pair.public_key, 0]

        call_data = [
            0x33434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2,
            0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463,
            len(account_initialize_call_data),
            *account_initialize_call_data
        ]
    elif provider == "braavos":
        class_hash = 0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e
        key_pair = KeyPair.from_private_key(private_key)
        salt = key_pair.public_key
        account_initialize_call_data = [key_pair.public_key]

        call_data = [
            0x5aa23d5bb71ddaa783da7ea79d405315bafa7cf0387a74f4593578c3e9e6570,
            0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a,
            len(account_initialize_call_data),
            *account_initialize_call_data
        ]
    elif provider == "braavos_old":
        class_hash = 0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e
        key_pair = KeyPair.from_private_key(private_key)
        salt = key_pair.public_key
        account_initialize_call_data = [key_pair.public_key]

        call_data = [
            0x69577e6756a99b584b5d1ce8e60650ae33b6e2b13541783458268f07da6b38a,
            0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a,
            len(account_initialize_call_data),
            *account_initialize_call_data
        ]
    elif provider == "argent_old":
        class_hash = 0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918
        key_pair = KeyPair.from_private_key(private_key)
        salt = key_pair.public_key
        account_initialize_call_data = [key_pair.public_key]

        call_data = [
            0x1a7820094feaf82d53f53f214b81292d717e7bb9a92bb2488092cd306f3993f,
            0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463,
            len(account_initialize_call_data),
            *account_initialize_call_data
        ]
    else:
        logger.error(f"Selected unsupported wallet provider: {provider}. Please select one of this: argent, braavos")
        return
    address = compute_address(
        salt=salt,
        class_hash=class_hash,  
        constructor_calldata=call_data,
        deployer_address=0,
    )
    

    account = Account(
            address=address, client=client, key_pair=key_pair, chain=chain
        )

    return account, call_data, salt, class_hash

async def sign_for_fee_estimate_braavos(
    provider, transaction
):
    version = transaction.version + 2**128
    transaction = dataclasses.replace(transaction, version=version)
    signature = sign_transaction_braavos(transaction, provider.signer.private_key)
    return _add_signature_to_transaction(tx=transaction, signature=signature)

async def _estimate_fee_braavos(
    provider,
    tx: AccountTransaction,
    block_hash = None,
    block_number = None,
):
    """
    :param tx: Transaction which fee we want to calculate.
    :param block_hash: a block hash.
    :param block_number: a block number.
    :return: Estimated fee.
    """
    tx = await sign_for_fee_estimate_braavos(provider, tx)
    estimated_fee = await provider._client.estimate_fee(
        tx=tx,
        block_hash=block_hash,
        block_number=block_number,
    )
    assert isinstance(estimated_fee, EstimatedFee)
    return estimated_fee

async def _get_max_fee_braavos_deploy(provider: Account, transaction, max_fee, auto_estimate):
    if auto_estimate and max_fee is not None:
        raise ValueError(
            "Arguments max_fee and auto_estimate are mutually exclusive."
        )
    
    if auto_estimate:
        estimated_fee = await _estimate_fee_braavos(provider, transaction)
        max_fee = int(estimated_fee.overall_fee * Account.ESTIMATED_FEE_MULTIPLIER)
    
    if max_fee is None:
        raise ValueError(
            "Argument max_fee must be specified when invoking a transaction."
        )
    return max_fee


async def sign_deploy_account_transaction_braavos(
    class_hash: int,
        contract_address_salt: int,
        constructor_calldata: Optional[List[int]] = None,
        *,
        nonce: int = 0,
        max_fee: Optional[int] = None,
        auto_estimate: bool = False,
        signer: Account
    ) -> DeployAccount:
    constructor_calldata = constructor_calldata or []

    deploy_account_tx = DeployAccount(
        class_hash=class_hash,
        contract_address_salt=contract_address_salt,
        constructor_calldata=constructor_calldata,
        version=1,
        max_fee=0,
        signature=[],
        nonce=nonce,
    )
    max_fee = await _get_max_fee_braavos_deploy(
            provider=signer, transaction=deploy_account_tx, max_fee=max_fee, auto_estimate=auto_estimate
        )
    deploy_account_tx = _add_max_fee_to_transaction(deploy_account_tx, max_fee)
    signature = sign_transaction_braavos(deploy_account_tx, signer.signer.private_key)
    return _add_signature_to_transaction(deploy_account_tx, signature)


async def deploy_account_braavos(
        *,
        address: AddressRepresentation,
        class_hash: int,
        salt: int,
        key_pair: KeyPair,
        client: Client,
        chain: StarknetChainId,
        constructor_calldata: Optional[List[int]] = None,
        nonce: int = 0,
        max_fee: Optional[int] = None,
        auto_estimate: bool = False,
    ) -> AccountDeploymentResult:
    # pylint: disable=too-many-locals
    """
    Deploys an account contract with provided class_hash on Starknet and returns
    an AccountDeploymentResult that allows waiting for transaction acceptance.
    Provided address must be first prefunded with enough tokens, otherwise the method will fail.
    If using Client for either TESTNET, TESTNET2 or MAINNET, this method will verify if the address balance
    is high enough to cover deployment costs.
    :param address: calculated and prefunded address of the new account.
    :param class_hash: class_hash of the account contract to be deployed.
    :param salt: salt used to calculate the address.
    :param key_pair: KeyPair used to calculate address and sign deploy account transaction.
    :param client: a Client instance used for deployment.
    :param chain: id of the Starknet chain used.
    :param constructor_calldata: optional calldata to account contract constructor. If ``None`` is passed,
        ``[key_pair.public_key]`` will be used as calldata.
    :param nonce: Nonce of the transaction.
    :param max_fee: max fee to be paid for deployment, must be less or equal to the amount of tokens prefunded.
    :param auto_estimate: Use automatic fee estimation, not recommend as it may lead to high costs.
    """
    address = parse_address(address)
    calldata = (
        constructor_calldata
        if constructor_calldata is not None
        else [key_pair.public_key]
    )
    if address != (
        computed := compute_address(
            salt=salt,
            class_hash=class_hash,
            constructor_calldata=calldata,
            deployer_address=0,
        )
    ):
        raise ValueError(
            f"Provided address {hex(address)} is different than computed address {hex(computed)} "
            f"for the given class_hash and salt."
        )

    account = Account(
        address=address, client=client, key_pair=key_pair, chain=chain
    )
    deploy_account_tx = await sign_deploy_account_transaction_braavos(
        class_hash=class_hash,
        contract_address_salt=salt,
        constructor_calldata=calldata,
        nonce=nonce,
        max_fee=max_fee,
        auto_estimate=auto_estimate,
        signer=account
    )
    if chain in (
        StarknetChainId.TESTNET,
        StarknetChainId.TESTNET2,
        StarknetChainId.MAINNET,
    ):
        balance = await account.get_balance()
        if balance < deploy_account_tx.max_fee:
            raise ValueError(
                "Not enough tokens at the specified address to cover deployment costs."
            )
    
    result = await client.deploy_account(deploy_account_tx)
    
    return AccountDeploymentResult(
        hash=result.transaction_hash, account=account, _client=account.client
    )
def transform_keys(keys):
    res = []
    for key in keys:
        try:
            try:
                res.append(int(key))
            except:
                res.append(int(key, 16))
        except Exception as e:
            logger.error(f"can't read key with following error: {e}")
    
    return res

def get_braavos_addr_from_private_key(private_key):
    class_hash = 0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e
    key_pair = KeyPair.from_private_key(private_key)
    salt = key_pair.public_key
    account_initialize_call_data = [key_pair.public_key]
    call_data = [
        0x5aa23d5bb71ddaa783da7ea79d405315bafa7cf0387a74f4593578c3e9e6570,
        0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a,
        len(account_initialize_call_data),
        *account_initialize_call_data
    ]
    address = compute_address(
        salt=salt,
        class_hash=class_hash,  
        constructor_calldata=call_data,
        deployer_address=0,
    )
    return address

def _sign_deploy_account_transaction_braavos(transaction: DeployAccount, private_key: int):
        contract_address = compute_address(
            salt=transaction.contract_address_salt,
            class_hash=transaction.class_hash,
            constructor_calldata=transaction.constructor_calldata,
            deployer_address=0,
        )
        tx_hash = compute_deploy_account_transaction_hash(
            contract_address=contract_address,
            class_hash=transaction.class_hash,
            constructor_calldata=transaction.constructor_calldata,
            salt=transaction.contract_address_salt,
            max_fee=transaction.max_fee,
            version=transaction.version,
            chain_id=23448594291968334,
            nonce=transaction.nonce,
        )
        
        tx_hash = compute_hash_on_elements([tx_hash, ACTUAL_IMPL, 0, 0, 0, 0, 0, 0, 0])

        # pylint: disable=invalid-name
        r, s = message_signature(msg_hash=tx_hash, priv_key=private_key)
        return [r, s, 0x2c2b8f559e1221468140ad7b2352b1a5be32660d0bf1a3ae3a054a4ec5254e4, 0, 0, 0, 0, 0, 0, 0]

def _sign_transaction_braavos(transaction: Invoke, private_key: int):
    tx_hash = compute_transaction_hash(
        tx_hash_prefix=TransactionHashPrefix.INVOKE,
        version=transaction.version,
        contract_address=get_braavos_addr_from_private_key(private_key),
        entry_point_selector=DEFAULT_ENTRY_POINT_SELECTOR,
        calldata=transaction.calldata,
        max_fee=transaction.max_fee,
        chain_id=23448594291968334,
        additional_data=[transaction.nonce],
    )
    # pylint: disable=invalid-name
    r, s = message_signature(msg_hash=tx_hash, priv_key=private_key)
    return [r, s, 0x2c2b8f559e1221468140ad7b2352b1a5be32660d0bf1a3ae3a054a4ec5254e4, 0, 0, 0, 0, 0, 0, 0]

def _sign_declare_transaction_braavos(transaction: Declare, private_key: int):
    tx_hash = compute_declare_transaction_hash(
        contract_class=transaction.contract_class,
        chain_id=23448594291968334,
        sender_address=get_braavos_addr_from_private_key(private_key),
        max_fee=transaction.max_fee,
        version=transaction.version,
        nonce=transaction.nonce,
    )
    # pylint: disable=invalid-name
    r, s = message_signature(msg_hash=tx_hash, priv_key=private_key)
    return [r, s, 0x2c2b8f559e1221468140ad7b2352b1a5be32660d0bf1a3ae3a054a4ec5254e4, 0, 0, 0, 0, 0, 0, 0]
def _sign_declare_v2_transaction_braavos(transaction: DeclareV2, private_key: int):
    tx_hash = compute_declare_v2_transaction_hash(
        contract_class=transaction.contract_class,
        compiled_class_hash=transaction.compiled_class_hash,
        chain_id=23448594291968334,
        sender_address=get_braavos_addr_from_private_key(private_key),
        max_fee=transaction.max_fee,
        version=transaction.version,
        nonce=transaction.nonce,
    )
    # pylint: disable=invalid-name
    r, s = message_signature(msg_hash=tx_hash, priv_key=private_key)
    return [r, s, 0x2c2b8f559e1221468140ad7b2352b1a5be32660d0bf1a3ae3a054a4ec5254e4, 0, 0, 0, 0, 0, 0, 0]

def sign_transaction_braavos(
        transaction: AccountTransaction, private_key: int
    ):
        if isinstance(transaction, Declare):
            return _sign_declare_transaction_braavos(transaction, private_key)
        if isinstance(transaction, DeclareV2):
            return _sign_declare_v2_transaction_braavos(transaction, private_key)
        if isinstance(transaction, DeployAccount):
            return _sign_deploy_account_transaction_braavos(transaction, private_key)
        return _sign_transaction_braavos(cast(Invoke, transaction), private_key)