try:
    from loguru import logger
    from utils import *
    from config import *
    client = GatewayClient(MAINNET)


    def main():
        with open("secrets.txt", "r") as f:
            keys = transform_keys(f.read().split("\n"))
        print("keys: ")
        for key in keys:
            print(hex(key))
        print("addresses: ")
        for key in keys:
            account, call_data, salt, class_hash = import_stark_account(key, client)
            print(hex(account.address))

    if __name__ == "__main__":
        main()
        input("Soft successfully end work. Press Enter to quit")
except Exception as e:
    logger.error(f"Got unexpected error: {e}")
    input("Soft successfully end work. Press Enter to quit")