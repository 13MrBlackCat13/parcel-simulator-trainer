import pymem
import struct
import time
import os
import json
import ctypes
import keyboard
import threading
import binascii


# Проверка прав администратора
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# Класс для работы с сигнатурами
class SignatureScanner:
    def __init__(self, process_handle):
        self.process_handle = process_handle

    # Создает сигнатуру из области памяти
    def create_signature(self, address, size=64):
        """Создает сигнатуру из области памяти вокруг указанного адреса"""
        try:
            # Определяем адрес начала сигнатуры (до адреса)
            start_addr = address - (size // 2)

            # Читаем блок памяти вокруг адреса
            memory_bytes = pymem.memory.read_bytes(self.process_handle, start_addr, size)

            # Вычисляем, где находится наше значение относительно начала блока
            value_offset = size // 2

            # Формируем сигнатуру как шестнадцатеричное представление байт
            signature = {
                'bytes': binascii.hexlify(memory_bytes).decode('ascii'),
                'offset': value_offset,
                'size': size
            }

            return signature
        except Exception as e:
            print(f"Ошибка при создании сигнатуры: {str(e)}")
            return None

    # Находит адрес по сигнатуре
    def find_signature(self, signature, start_addr=None, size=None):
        """Находит адрес по сигнатуре в памяти процесса"""
        if not signature or 'bytes' not in signature:
            return None

        # Преобразуем сигнатуру обратно в байты
        try:
            pattern = binascii.unhexlify(signature['bytes'])
            offset = signature.get('offset', 0)
        except Exception as e:
            print(f"Ошибка при обработке сигнатуры: {str(e)}")
            return None

        # Получаем регионы памяти для сканирования
        memory_regions = []

        if start_addr is not None and size is not None:
            # Используем заданный регион
            memory_regions.append((start_addr, size))
        else:
            # Получаем все доступные регионы
            address = 0
            while True:
                try:
                    mbi = pymem.memory.virtual_query(self.process_handle, address)
                    address = mbi.BaseAddress + mbi.RegionSize

                    # Проверяем, подходит ли регион для сканирования
                    if (mbi.State == pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT and
                            mbi.Protect & pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE):
                        memory_regions.append((mbi.BaseAddress, mbi.RegionSize))

                    # Проверка на конец адресного пространства
                    if address > 0x7FFFFFFFFFFF:
                        break

                except Exception:
                    # Пропускаем недоступные регионы
                    address += 0x1000
                    if address > 0x7FFFFFFFFFFF:
                        break

        print("Поиск сигнатуры в памяти...")

        # Сканируем регионы памяти на наличие сигнатуры
        for base_addr, region_size in memory_regions:
            try:
                # Читаем регион памяти
                buffer = pymem.memory.read_bytes(self.process_handle, base_addr, region_size)

                # Ищем сигнатуру в буфере
                pos = buffer.find(pattern)
                if pos != -1:
                    # Сигнатура найдена! Вычисляем адрес с учетом смещения
                    result_addr = base_addr + pos + offset
                    print(f"Найдена сигнатура по адресу {hex(result_addr)}")
                    return result_addr

            except Exception:
                # Пропускаем ошибки чтения памяти
                continue

        return None


# Класс для работы с разными типами данных
class MemoryDataType:
    INT32 = 1
    FLOAT = 2
    DOUBLE = 3
    INT64 = 4

    @staticmethod
    def get_size(data_type):
        if data_type == MemoryDataType.INT32:
            return 4
        elif data_type == MemoryDataType.FLOAT:
            return 4
        elif data_type == MemoryDataType.DOUBLE:
            return 8
        elif data_type == MemoryDataType.INT64:
            return 8
        return 4

    @staticmethod
    def pack_value(value, data_type):
        if data_type == MemoryDataType.INT32:
            return struct.pack("<i", int(value))
        elif data_type == MemoryDataType.FLOAT:
            return struct.pack("<f", float(value))
        elif data_type == MemoryDataType.DOUBLE:
            return struct.pack("<d", float(value))
        elif data_type == MemoryDataType.INT64:
            return struct.pack("<q", int(value))
        return struct.pack("<i", int(value))

    @staticmethod
    def unpack_value(buffer, data_type):
        if data_type == MemoryDataType.INT32:
            return struct.unpack("<i", buffer)[0]
        elif data_type == MemoryDataType.FLOAT:
            return struct.unpack("<f", buffer)[0]
        elif data_type == MemoryDataType.DOUBLE:
            return struct.unpack("<d", buffer)[0]
        elif data_type == MemoryDataType.INT64:
            return struct.unpack("<q", buffer)[0]
        return struct.unpack("<i", buffer)[0]


# Класс для дифференциального сканирования памяти
class DifferentialMemoryScanner:
    def __init__(self, process_handle):
        self.process_handle = process_handle
        self.memory_regions = []
        self.scan_results = []
        self.stop_scan = False

    # Получение доступных регионов памяти
    def get_memory_regions(self):
        regions = []
        address = 0

        print("Поиск доступных регионов памяти...")

        while True:
            try:
                mbi = pymem.memory.virtual_query(self.process_handle, address)
                address = mbi.BaseAddress + mbi.RegionSize

                # Проверяем, подходит ли регион для сканирования
                if (mbi.State == pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT and
                        mbi.Protect & pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE and
                        mbi.Protect != pymem.ressources.structure.MEMORY_PROTECTION.PAGE_GUARD and
                        mbi.RegionSize > 0):
                    regions.append((mbi.BaseAddress, mbi.RegionSize))

                # Проверка на конец адресного пространства
                if address > 0x7FFFFFFFFFFF:
                    break

            except Exception as e:
                # Пропускаем недоступные регионы
                address += 0x1000
                if address > 0x7FFFFFFFFFFF:
                    break

        self.memory_regions = regions
        print(f"Найдено {len(regions)} доступных регионов памяти")

    # Первое сканирование - поиск значения
    def first_scan(self, value, data_type=MemoryDataType.INT32):
        if not self.memory_regions:
            self.get_memory_regions()

        size = MemoryDataType.get_size(data_type)
        value_bytes = MemoryDataType.pack_value(value, data_type)

        print(f"Начинаем первое сканирование для значения {value}...")

        # Создаем поток для обработки нажатия ESC
        self.stop_scan = False

        def check_for_esc():
            print("Нажмите ESC для остановки сканирования")
            while True:
                if keyboard.is_pressed('esc'):
                    print("\nПолучена команда на остановку сканирования")
                    self.stop_scan = True
                    break
                time.sleep(0.1)

        esc_thread = threading.Thread(target=check_for_esc)
        esc_thread.daemon = True
        esc_thread.start()

        start_time = time.time()
        addresses = []

        # Сканируем регионы памяти
        for i, (base_addr, region_size) in enumerate(self.memory_regions):
            if self.stop_scan:
                break

            try:
                # Показываем прогресс
                if i % 10 == 0:
                    elapsed = time.time() - start_time
                    progress = (i / len(self.memory_regions)) * 100
                    print(
                        f"\rПрогресс: {progress:.1f}% | Регион {i + 1}/{len(self.memory_regions)} | Найдено: {len(addresses)}",
                        end="")

                # Читаем регион памяти
                buffer = pymem.memory.read_bytes(self.process_handle, base_addr, region_size)

                # Ищем значение в буфере
                offset = 0
                while True:
                    offset = buffer.find(value_bytes, offset)
                    if offset == -1:
                        break

                    addr = base_addr + offset
                    addresses.append(addr)
                    offset += size

            except Exception as e:
                # Пропускаем ошибки чтения памяти
                continue

        elapsed = time.time() - start_time
        print(f"\nСканирование завершено за {elapsed:.2f} секунд")
        print(f"Найдено {len(addresses)} адресов со значением {value}")

        self.scan_results = addresses
        return addresses

    # Следующее сканирование - фильтрация результатов
    def next_scan(self, value, data_type=MemoryDataType.INT32):
        if not self.scan_results:
            print("Нет результатов предыдущего сканирования")
            return []

        print(f"Фильтрация результатов для значения {value}...")

        size = MemoryDataType.get_size(data_type)
        matching_addresses = []

        for addr in self.scan_results:
            try:
                # Читаем текущее значение по адресу
                buffer = pymem.memory.read_bytes(self.process_handle, addr, size)
                current_value = MemoryDataType.unpack_value(buffer, data_type)

                # Проверяем, совпадает ли значение
                if abs(current_value - value) < 0.01:  # Для чисел с плавающей точкой
                    matching_addresses.append(addr)
            except Exception as e:
                # Пропускаем ошибки чтения памяти
                continue

        print(f"Осталось {len(matching_addresses)} адресов со значением {value}")

        self.scan_results = matching_addresses
        return matching_addresses

    # Сканирование с учетом изменений
    def changed_value_scan(self, change_type="changed"):
        if not self.scan_results:
            print("Нет результатов предыдущего сканирования")
            return []

        print(f"Фильтрация результатов по изменению значения ({change_type})...")

        # Сохраняем текущие значения
        current_values = {}
        for addr in self.scan_results:
            try:
                # Читаем текущее значение по адресу (предполагаем INT32)
                buffer = pymem.memory.read_bytes(self.process_handle, addr, 4)
                current_values[addr] = struct.unpack("<i", buffer)[0]
            except Exception as e:
                # Пропускаем ошибки чтения памяти
                continue

        # Просим пользователя изменить значение в игре
        print("Пожалуйста, измените значение денег в игре (заработайте или потратьте).")
        input("Нажмите Enter, когда изменение будет выполнено...")

        # Проверяем, какие значения изменились
        matching_addresses = []
        for addr, old_value in current_values.items():
            try:
                # Читаем новое значение
                buffer = pymem.memory.read_bytes(self.process_handle, addr, 4)
                new_value = struct.unpack("<i", buffer)[0]

                # Проверяем условие изменения
                if change_type == "changed" and old_value != new_value:
                    matching_addresses.append(addr)
                    print(f"Адрес {hex(addr)}: {old_value} -> {new_value}")
                elif change_type == "increased" and new_value > old_value:
                    matching_addresses.append(addr)
                    print(f"Адрес {hex(addr)}: {old_value} -> {new_value} (увеличилось)")
                elif change_type == "decreased" and new_value < old_value:
                    matching_addresses.append(addr)
                    print(f"Адрес {hex(addr)}: {old_value} -> {new_value} (уменьшилось)")
            except Exception as e:
                # Пропускаем ошибки чтения памяти
                continue

        print(f"Осталось {len(matching_addresses)} адресов после фильтрации")

        self.scan_results = matching_addresses
        return matching_addresses


# Основной класс программы
class MoneyChanger:
    def __init__(self):
        self.process_name = "parcel-Win64-Shipping.exe"
        self.display_name = "Parcel Simulator"
        self.pm = None
        self.process_handle = None
        self.money_addresses = []
        self.save_file = "parcel_money_data.json"
        self.scanner = None
        self.signature_scanner = None
        self.current_money = 0
        self.signatures = []

    # Подключение к процессу игры
    def connect_to_game(self):
        try:
            print(f"Подключение к игре {self.display_name}...")
            self.pm = pymem.Pymem(self.process_name)
            self.process_handle = self.pm.process_handle
            print(f"Успешно подключились к игре! (ID процесса: {self.pm.process_id})")

            # Создаем сканеры
            self.scanner = DifferentialMemoryScanner(self.process_handle)
            self.signature_scanner = SignatureScanner(self.process_handle)

            return True
        except pymem.exception.ProcessNotFound:
            print(f"Процесс {self.process_name} не найден.")
            print("Убедитесь, что игра запущена и попробуйте снова.")
            return False
        except Exception as e:
            print(f"Ошибка при подключении к игре: {str(e)}")
            return False

    # Загрузка сохраненных данных
    def load_saved_data(self):
        if not os.path.exists(self.save_file):
            return False

        try:
            with open(self.save_file, 'r') as f:
                data = json.load(f)

                # Загружаем адреса
                if 'addresses' in data:
                    addresses = [int(addr, 16) for addr in data['addresses']]
                    print(f"Загружено {len(addresses)} сохраненных адресов.")

                    # Проверяем валидность адресов
                    valid_addresses = []
                    for addr in addresses:
                        try:
                            value = self.pm.read_int(addr)
                            if 0 <= value <= 10000000:  # Разумный диапазон для денег
                                valid_addresses.append(addr)
                                print(f"Адрес {hex(addr)}: значение = {value}")
                        except:
                            continue

                    if valid_addresses:
                        self.money_addresses = valid_addresses
                        print(f"Найдено {len(valid_addresses)} действительных адресов.")

                        # Считываем текущее значение денег
                        try:
                            self.current_money = self.pm.read_int(valid_addresses[0])
                            print(f"Текущее количество денег: {self.current_money}")
                        except:
                            pass

                        return True

                # Пробуем использовать сигнатуры
                if 'signatures' in data and not self.money_addresses:
                    print("Пробуем использовать сохраненные сигнатуры...")
                    self.signatures = data['signatures']

                    for i, signature in enumerate(self.signatures):
                        # Ищем адрес по сигнатуре
                        addr = self.signature_scanner.find_signature(signature)
                        if addr:
                            # Пробуем прочитать значение
                            try:
                                value = self.pm.read_int(addr)
                                if 0 <= value <= 10000000:  # Проверка на разумное значение
                                    self.money_addresses.append(addr)
                                    self.current_money = value
                                    print(f"Найден адрес {hex(addr)} по сигнатуре {i + 1}: значение = {value}")
                            except:
                                pass

                    if self.money_addresses:
                        print(f"Успешно найдено {len(self.money_addresses)} адресов по сигнатурам.")
                        return True

            print("Не удалось найти действующие адреса или сигнатуры.")
            return False

        except Exception as e:
            print(f"Ошибка при загрузке данных: {str(e)}")
            return False

    # Сохранение данных
    def save_data(self):
        try:
            data = {
                'addresses': [hex(addr) for addr in self.money_addresses],
                'signatures': self.signatures,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }

            with open(self.save_file, 'w') as f:
                json.dump(data, f, indent=4)

            print(f"Данные сохранены в файл {self.save_file}")
        except Exception as e:
            print(f"Ошибка при сохранении данных: {str(e)}")

    # Создание сигнатур
    def create_signature(self, address):
        # Создаем сигнатуру
        print("Создание сигнатуры для адреса денег...")
        signature = self.signature_scanner.create_signature(address)
        if signature:
            self.signatures.append(signature)
            print("Сигнатура успешно создана!")

        # Сохраняем данные
        self.save_data()

    # Проверка адресов путем изменения значения
    def verify_addresses(self, addresses, test_value):
        if not addresses:
            print("Нет адресов для проверки.")
            return []

        # Группируем адреса для проверки (если их много)
        grouped_addresses = []
        for i in range(0, len(addresses), 5):
            grouped_addresses.append(addresses[i:i + 5])

        # Если адресов немного, проверяем каждый отдельно
        if len(addresses) <= 5:
            grouped_addresses = [[addr] for addr in addresses]

        print(f"Проверка {len(addresses)} адресов...")

        # Сохраняем оригинальные значения
        original_values = {}
        for addr in addresses:
            try:
                original_values[addr] = self.pm.read_int(addr)
            except:
                continue

        verified_addresses = []

        # Проверяем каждую группу или отдельный адрес
        for i, group in enumerate(grouped_addresses):
            print(f"\nПроверка группы {i + 1}/{len(grouped_addresses)} ({len(group)} адресов)")

            # Выводим адреса группы
            for addr in group:
                try:
                    current_value = self.pm.read_int(addr)
                    print(f"  {hex(addr)}: текущее значение = {current_value}")
                except:
                    print(f"  {hex(addr)}: ошибка чтения")

            # Изменяем значения всех адресов в группе
            for addr in group:
                try:
                    if addr in original_values:
                        self.pm.write_int(addr, test_value)
                except Exception as e:
                    print(f"Ошибка при записи в адрес {hex(addr)}: {str(e)}")

            print(f"Установлено значение {test_value}.")
            print("Проверьте, изменилось ли количество денег в игре.")

            # Спрашиваем пользователя, изменились ли деньги
            response = input("Деньги изменились? (y/n): ").lower()

            if response == 'y':
                # Если группа содержит только один адрес, просто добавляем его
                if len(group) == 1:
                    verified_addresses.append(group[0])
                    print(f"Адрес {hex(group[0])} подтвержден!")
                else:
                    # Проверяем каждый адрес в группе отдельно
                    print("Группа содержит нужные адреса! Проверяем каждый адрес отдельно...")

                    # Восстанавливаем все значения
                    for addr, value in original_values.items():
                        try:
                            self.pm.write_int(addr, value)
                        except:
                            pass

                    # Проверяем каждый адрес
                    for addr in group:
                        if addr not in original_values:
                            continue

                        try:
                            # Изменяем только один адрес
                            orig_value = original_values[addr]
                            self.pm.write_int(addr, test_value)

                            print(f"Адрес {hex(addr)}: установлено значение {test_value}.")
                            print("Проверьте, изменилось ли количество денег в игре.")

                            resp = input("Деньги изменились? (y/n): ").lower()
                            if resp == 'y':
                                verified_addresses.append(addr)
                                print(f"Адрес {hex(addr)} подтвержден!")

                            # Восстанавливаем значение
                            self.pm.write_int(addr, orig_value)

                        except Exception as e:
                            print(f"Ошибка при проверке адреса {hex(addr)}: {str(e)}")

            # Восстанавливаем оригинальные значения для всей группы
            for addr in group:
                if addr in original_values:
                    try:
                        self.pm.write_int(addr, original_values[addr])
                    except:
                        continue

        print(f"\nПроверка завершена. Найдено {len(verified_addresses)} подтвержденных адресов.")
        return verified_addresses

    # Поиск адреса денег
    def find_money_address(self):
        print("Поиск адреса денег в памяти игры...")

        # Сначала пробуем загрузить сохраненные данные
        if self.load_saved_data():
            print("Успешно загружены сохраненные данные.")

            # Если найдены адреса, но нет сигнатур, создаем их
            if self.money_addresses and not self.signatures:
                print("Найдены адреса, но нет сигнатур. Создаем их...")
                self.create_signature(self.money_addresses[0])

            return True

        print("\nДля поиска адреса денег будет использован метод дифференциального сканирования.")
        print("Этот метод позволяет найти адрес, даже если он меняется при перезапуске игры.")

        # Спрашиваем текущее значение денег
        try:
            current_money = int(input("Введите текущее количество денег в игре: "))
        except ValueError:
            print("Неверный ввод. Введите число.")
            return False

        # Выполняем первое сканирование
        print("Выполняем первое сканирование...")
        self.scanner.first_scan(current_money)

        if not self.scanner.scan_results:
            # Пробуем другие типы данных
            print("Не найдено адресов с целочисленным значением. Пробуем Float...")
            self.scanner.first_scan(current_money, MemoryDataType.FLOAT)

        if not self.scanner.scan_results:
            print("Не удалось найти адреса. Возможно, игра использует нестандартный формат данных.")
            return False

        # Если найдено слишком много адресов, фильтруем их с помощью дифференциального сканирования
        if len(self.scanner.scan_results) > 100:
            print("\nНайдено слишком много адресов. Выполните следующие действия:")
            print("1. Измените количество денег в игре (заработайте или потратьте немного)")
            print("2. Введите новое значение денег")

            try:
                new_money = int(input("Введите новое количество денег после изменения: "))
            except ValueError:
                print("Неверный ввод. Введите число.")
                return False

            # Фильтруем результаты по новому значению
            self.scanner.next_scan(new_money)

        # Если всё еще много адресов, используем сканирование по изменению
        if len(self.scanner.scan_results) > 20:
            print("\nВсё еще много адресов. Выполним сканирование по изменению.")
            self.scanner.changed_value_scan()

        # Проверяем найденные адреса
        if self.scanner.scan_results:
            test_value = current_money + 1000
            print(f"\nПроверка найденных адресов с тестовым значением {test_value}...")

            verified_addresses = self.verify_addresses(self.scanner.scan_results, test_value)

            if verified_addresses:
                self.money_addresses = verified_addresses
                self.current_money = current_money

                # Создаем сигнатуры для найденных адресов
                if verified_addresses:
                    self.create_signature(verified_addresses[0])

                return True

        print("Не удалось подтвердить адреса денег.")
        return False

    # Изменение значения денег
    def change_money(self, new_value):
        if not self.money_addresses:
            print("Адрес денег не найден. Сначала выполните поиск.")
            return False

        success = False
        for addr in self.money_addresses:
            try:
                self.pm.write_int(addr, new_value)
                print(f"Значение успешно изменено по адресу {hex(addr)}")
                success = True
            except Exception as e:
                print(f"Ошибка при записи значения по адресу {hex(addr)}: {str(e)}")

        if success:
            self.current_money = new_value
            return True
        else:
            print("Не удалось изменить значение ни по одному адресу.")
            return False

    # Закрытие соединения с процессом
    def disconnect(self):
        if self.pm:
            self.pm.close_process()
            print("Отключено от процесса игры.")


# Основная функция
def main():
    # Проверка прав администратора
    if not is_admin():
        print("Эта программа требует прав администратора для доступа к памяти игры.")
        print("Пожалуйста, запустите программу от имени администратора.")
        input("Нажмите Enter для выхода...")
        return

    print("=== Модификатор денег для Parcel Simulator ===")
    print("Версия 7.0 - С сигнатурами")

    # Создаем экземпляр модификатора
    changer = MoneyChanger()

    # Подключаемся к процессу игры
    if not changer.connect_to_game():
        input("Нажмите Enter для выхода...")
        return

    # Ищем адрес денег
    if not changer.find_money_address():
        print("Не удалось найти адрес денег. Возможно, игра использует нестандартный формат данных.")
        input("Нажмите Enter для выхода...")
        return

    # Главное меню программы
    while True:
        print("\n=== Меню ===")
        print(f"Текущее количество денег: {changer.current_money}")
        print("1. Изменить количество денег")
        print("2. Найти адрес денег заново")
        print("0. Выход")

        choice = input("Выберите действие: ")

        if choice == "1":
            try:
                new_money = int(input("Введите новое количество денег: "))
                if changer.change_money(new_money):
                    print("Деньги успешно изменены!")
                else:
                    print("Не удалось изменить деньги.")
            except ValueError:
                print("Некорректный ввод. Введите число.")

        elif choice == "2":
            changer.find_money_address()

        elif choice == "0":
            print("Закрытие программы...")
            changer.disconnect()
            break

        else:
            print("Неверный выбор. Попробуйте снова.")


# Запуск программы
if __name__ == "__main__":
    main()