try:
    from loguru import logger
    from utils import *

    client = GatewayClient(MAINNET)


    async def deploy_account(account: Account, call_data: list, salt: int, class_hash: int, delay: int):
        await asyncio.sleep(delay)
        balance = 0
        while True:
            try:
                nonce = await account.get_nonce()
                if nonce > 0:
                    logger.info(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] already deployed. Skip")
                    return
                else:
                    break
            except Exception as e:
                logger.error(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] got error while trying to get nonce: {e}")
                await sleeping('0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::], True)
        while True:
            
            logger.info(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] checking balance.")
            try:
                balance = await account.get_balance()
                logger.info(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] got balance: {balance/1e18} ETH")
                if balance >= 1e14:
                    break
                await sleeping('0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::])

            except Exception as e:
                logger.error(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] got error while trying to get balance: {e}")
                await sleeping('0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::], True)
        logger.success(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] found balance. Going to deploy")
        i = 0
        while i < retries_limit:
            i += 1
            try:
                
                if provider == "argent":
                    account_deployment_result = await Account.deploy_account(
                        address=account.address,
                        class_hash=class_hash,
                        salt=salt,
                        key_pair=account.signer.key_pair,
                        client=account.client,
                        chain=chain,
                        constructor_calldata=call_data,
                        auto_estimate=True,
                    )
                elif provider == "braavos":
                    account_deployment_result = await deploy_account_braavos(
                        address=account.address,
                        class_hash=class_hash,
                        salt=salt,
                        key_pair=account.signer.key_pair,
                        client=account.client,
                        chain=chain,
                        constructor_calldata=call_data,
                        max_fee=int(55e13),
                    )
                else:
                    logger.error(f"Selected unsupported wallet provider: {provider}. Please select one of this: argent, braavos")
                    return

                # Wait for deployment transaction to be accepted

                await account_deployment_result.wait_for_acceptance()
                # From now on, account can be used as usual
                account = account_deployment_result.account
                logger.success(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] deployed successfully, txn hash: {hex(account_deployment_result.hash)}")
                return 1

            except Exception as e:
                logger.error(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] got error, while deploying account, {e}")
                await sleeping('0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::], True)
        logger.error(f"[{'0x' + '0'*(66-len(hex(account.address))) + hex(account.address)[2::]}] already deploying")
        return -1

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

    def main():
        with open("secrets.txt", "r") as f:
            keys = transform_keys(f.read().split("\n"))

        
        loop = asyncio.new_event_loop()
        tasks = []
        delay = 0
        for key in keys:
            account, call_data, salt, class_hash = import_stark_account(key, client)
            tasks.append(loop.create_task(deploy_account(account, call_data, salt, class_hash, delay)))
            delay += get_random_value_int(ThreadRunnerSleep)

        loop.run_until_complete(asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED))

    if __name__ == "__main__":
        main()
        input("Soft successfully end work. Press Enter to quit")


except Exception as e:
    logger.error(f"Got unexpected error: {e}")
    input("Soft successfully end work. Press Enter to quit")