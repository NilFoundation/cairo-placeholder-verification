import solcx

from web3_test_defs import contracts_dir
from web3 import Web3
from web3.middleware import geth_poa_middleware

def init_connection():
    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    w3.eth.default_account = w3.eth.accounts[0]
    return w3


def find_compiled_contract(compiled, contract_name):
    compiled_id = None
    compiled_interface = False
    for key, value in compiled.items():
        if key.endswith(contract_name):
            compiled_id = key
            compiled_interface = value
            break
    else:
        print(f'{contract_name} not found!')
        exit(1)
    return compiled_id, compiled_interface

def write_tx_calldata(w3, tx_receipt, ofname = 'tx_calldata.txt'):
    with open(ofname, 'w') as f:
        f.write(w3.eth.get_transaction(tx_receipt.transactionHash).input)

def print_tx_info(w3, tx_receipt, tx_name):
    print(tx_name)
    print(tx_receipt.transactionHash.hex())
    print('gasUsed =', tx_receipt.gasUsed)
    write_tx_calldata(w3, tx_receipt)

def deploy_link_libs(w3, compiled, test_contract_bytecode, linked_libs_names):
    linked_bytecode = test_contract_bytecode
    for lib_name in linked_libs_names:
        compiled_lib_id, component_lib = find_compiled_contract(compiled, lib_name)
        component_lib_bytecode = component_lib['bin']
        component_lib_abi = component_lib['abi']
        print(f'Lib {lib_name} bytecode size:', len(component_lib_bytecode) // 2)
        contract_lib = w3.eth.contract(
            abi=component_lib_abi, bytecode=component_lib_bytecode)
        deploy_lib_tx_hash = contract_lib.constructor().transact()
        deploy_lib_tx_receipt = w3.eth.wait_for_transaction_receipt(deploy_lib_tx_hash)
        linked_bytecode = solcx.link_code(
            linked_bytecode,
            {compiled_lib_id: deploy_lib_tx_receipt.contractAddress},
            solc_version="0.8.12")
    print('Bytecode size:', len(linked_bytecode) // 2)
    return linked_bytecode


def do_placeholder_verification_test_via_transact(test_contract_name, test_contract_path, linked_libs_names, init_test_params_func):
    w3 = init_connection()

    compiled = solcx.compile_files(
        [f'{contracts_dir}/{test_contract_path}'],
        output_values=['abi', 'bin'],
        solc_version="0.8.12",
        optimize=True,
        optimize_runs=200)

    compiled_test_contract_id, compiled_test_contract_interface = find_compiled_contract(
        compiled, test_contract_name)
    bytecode = compiled_test_contract_interface['bin']
    abi = compiled_test_contract_interface['abi']
    bytecode = deploy_link_libs(w3, compiled, bytecode, linked_libs_names)

    test_contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    deploy_tx_hash = test_contract.constructor().transact()
    deploy_tx_receipt = w3.eth.wait_for_transaction_receipt(deploy_tx_hash)
    print("Deployment:", deploy_tx_receipt.gasUsed)

    test_contract_inst = w3.eth.contract(
        address=deploy_tx_receipt.contractAddress, abi=abi)
    params = init_test_params_func()
    run_tx_hash = test_contract_inst.functions.verify(
        params['proof'], params['init_params'], params['columns_rotations']).transact()
    run_tx_receipt = w3.eth.wait_for_transaction_receipt(run_tx_hash)
    print_tx_info(w3, run_tx_receipt, params['_test_name'])

