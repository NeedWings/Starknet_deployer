# Starknet-deployer

**With love for : https://t.me/swiper_tools**

**Приобрести бота на ZkSync / LayerZero / Starknet можно тут: https://t.me/swipersoft_bot**

**DEV           : https://t.me/WingedGarage**


# Features

- **Поддержка Браавос и Аргент**
- **Герератор кошельков вместе с сид фразами**
- **Вывод адресов из приватных ключей**

### Settings

Смотри config.py file

~~~python
retries_limit = 10 # отвечает за кол-во ретраев
provider = "argent" # argent или braavos
TaskSleep = [10, 20] # задержка между поисками балансов
ErrorSleepeng = [10, 20] # задержка при ошибке
ThreadRunnerSleep = [10, 20] # задержка между кошельками
amount_to_create = 10 # сколько кошельков создавать

~~~

Чтобы начать работу:
 - Загрузи приватники в файл secrets.txt
 - Выбери нужный тебе провайдер
 - запусти main.py

### How to run script
1. Устанавливаем Python: https://www.python.org/downloads/, я использую версию 3.9.8
2. При установке ставим галочку на PATH при установке

>![ScreenShot](https://img2.teletype.in/files/19/03/19032fbe-1912-4bf4-aed6-0f304c9bf12e.png)

3. После установки скачиваем бота, переносим все файлы в одну папку (создаете сами, в названии и пути к папке не должно быть кириллицы и пробелов)
4. Запускаем консоль (win+r -> cmd)
5. Пишем в консоль:
cd /d Директория
* Директория - путь к папке, где лежит скрипт (само название скрипта писать не нужно)
6. Прописываем:
pip install -r requirements.txt
7. После установки всех библиотек командой выше, запускаем софт:

Для деплоера:
python main.py

Для генератора(Кошельки будут в файле wallets.csv):
python generator.py        


Для вывода адресов:
python address_from_keys.py

Скрипт запустился.
