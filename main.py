import pymem
import pymem.process
import struct
import time
import os
import ctypes
import json
from datetime import datetime


# Проверка прав администратора
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# Класс для работы с памятью игры Parcel Simulator
class ParcelMoneyModifier:
    def __init__(self):
        self.process_name = "parcel-Win64-Shipping.exe"
        self.display_name = "Parcel Simulator"
        self.pm = None
        self.money_addresses = []
        self.save_file = "parcel_addresses.json"
        self.current_money = 0

        # Приоритетные адреса на основе анализа предыдущих запусков
        self.priority_addresses = [
            0x24A1698D878  # Адрес, который точно обновляется при изменении денег
        ]

    # Подключение к процессу игры
    def connect_to_game(self):
        try:
            print(f"Подключение к игре {self.display_name}...")
            self.pm = pymem.Pymem(self.process_name)
            print(f"Успешно подключились к игре! (ID процесса: {self.pm.process_id})")
            return True
        except pymem.exception.ProcessNotFound:
            print(f"Процесс {self.process_name} не найден.")
            print("Убедитесь, что игра запущена и попробуйте снова.")
            return False
        except Exception as e:
            print(f"Ошибка при подключении к игре: {str(e)}")
            return False

    # Загрузка сохраненных адресов из файла
    def load_saved_addresses(self):
        if not os.path.exists(self.save_file):
            return False

        try:
            with open(self.save_file, 'r') as f:
                data = json.load(f)

                if 'addresses' not in data:
                    return False

                # Загружаем адреса из файла
                self.money_addresses = [int(addr, 16) for addr in data['addresses']]
                print(f"Загружено {len(self.money_addresses)} сохраненных адресов.")

                # Проверяем валидность адресов
                valid_addresses = []
                for addr in self.money_addresses:
                    try:
                        value = self.pm.read_int(addr)
                        valid_addresses.append(addr)
                    except:
                        continue

                if len(valid_addresses) > 0:
                    self.money_addresses = valid_addresses
                    print(f"Проверено и подтверждено {len(valid_addresses)} адресов.")

                    # Получаем текущее значение денег из первого адреса
                    try:
                        # Если есть приоритетный адрес в списке, используем его
                        priority_addr = next((addr for addr in valid_addresses if addr in self.priority_addresses),
                                             None)
                        if priority_addr:
                            self.current_money = self.pm.read_int(priority_addr)
                        else:
                            self.current_money = self.pm.read_int(valid_addresses[0])
                        print(f"Текущее количество денег: {self.current_money}")
                    except:
                        pass

                    return True
                else:
                    print("Ни один из сохраненных адресов не валиден в этой сессии игры.")
                    return False

        except Exception as e:
            print(f"Ошибка при загрузке сохраненных адресов: {str(e)}")
            return False

    # Сохранение адресов в файл
    def save_addresses(self):
        if not self.money_addresses:
            return

        try:
            data = {
                'addresses': [hex(addr) for addr in self.money_addresses],
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            with open(self.save_file, 'w') as f:
                json.dump(data, f, indent=4)

            print(f"Адреса сохранены в файл {self.save_file}")
        except Exception as e:
            print(f"Ошибка при сохранении адресов: {str(e)}")

    # Сканирование известных адресов (используя закономерности из прошлых сканирований)
    def scan_known_patterns(self, value):
        print("Быстрое сканирование известных областей памяти...")

        # Сначала проверяем приоритетные адреса
        priority_results = []
        print("Проверка приоритетных адресов:")
        for addr in self.priority_addresses:
            try:
                read_value = self.pm.read_int(addr)
                print(f"  Адрес {hex(addr)}: текущее значение = {read_value}")
                if read_value == value:
                    priority_results.append(addr)
                    print(f"  Найдено совпадение! Этот адрес содержит искомое значение {value}")
            except Exception as e:
                print(f"  Ошибка при чтении адреса {hex(addr)}: {str(e)}")

        # Шаблоны адресов, основанные на предыдущих результатах
        patterns = [
            "24A16672", "24A16674", "24A1667D", "24A1698D",
            "24AC0972", "24ACA332", "24AEC950", "24AEC951",
            "24AEC952", "24AEC953", "24AEC954", "24AEC957",
            "24AEC959", "24AEC95C", "24AEC95E", "24AEC95F",
            "24AF7503"
        ]

        results = []
        found_count = 0

        print("Сканирование по известным шаблонам адресов...")
        for pattern in patterns:
            # Преобразуем шаблон в диапазон адресов
            start_addr = int(pattern + "000", 16)
            end_addr = int(pattern + "FFF", 16)
            print(f"Проверка диапазона {hex(start_addr)} - {hex(end_addr)}")

            # Сканируем заданный диапазон
            try:
                # Читаем весь диапазон памяти
                buffer = self.pm.read_bytes(start_addr, end_addr - start_addr)

                # Ищем значение в буфере
                value_bytes = struct.pack("<I", value)
                offset = 0
                pattern_found = 0

                while True:
                    offset = buffer.find(value_bytes, offset)
                    if offset == -1:
                        break

                    found_address = start_addr + offset
                    results.append(found_address)
                    found_count += 1
                    pattern_found += 1
                    offset += 4

                print(f"  Найдено {pattern_found} адресов в этом диапазоне")

            except Exception as e:
                # Пропускаем ошибки чтения памяти
                continue

        # Объединяем результаты с приоритетными адресами
        combined_results = list(set(priority_results + results))
        print(f"Всего найдено {len(combined_results)} адресов со значением {value}")

        return combined_results

    # Автоматическая проверка адресов путем наблюдения за их изменениями
    def auto_verify_addresses(self, all_addresses, test_value):
        """
        Автоматически проверяет адреса, изменяя значение и наблюдая, какие адреса изменяются в ответ
        """
        print("\nАвтоматическая проверка адресов:")
        print("В следующих шагах программа изменит значение денег в игре и")
        print("проверит, какие адреса изменяются в ответ на это изменение.")
        print("Подтвердите, что вы хотите продолжить (y/n):")

        if input().lower() != 'y':
            print("Автоматическая проверка отменена.")
            return []

        # Сохраняем текущие значения всех адресов
        current_values = {}
        for addr in all_addresses:
            try:
                current_values[addr] = self.pm.read_int(addr)
            except:
                pass

        print(f"Сохранено {len(current_values)} текущих значений.")
        print(f"Текущие значения для приоритетных адресов:")
        for addr in self.priority_addresses:
            if addr in current_values:
                print(f"  {hex(addr)}: {current_values[addr]}")

        # Устанавливаем тестовое значение для всех адресов
        print(f"\nУстановка тестового значения {test_value} для всех адресов...")
        for addr in current_values.keys():
            try:
                self.pm.write_int(addr, test_value)
            except Exception as e:
                print(f"Ошибка при записи в адрес {hex(addr)}: {str(e)}")

        # Даем пользователю проверить, изменились ли деньги в игре
        print("\nПроверьте, что количество денег в игре изменилось на", test_value)
        print("Подтвердите, что деньги изменились (y/n):")

        money_changed = input().lower() == 'y'

        if not money_changed:
            print("Вы указали, что деньги не изменились. Проверка будет проведена вручную.")

            # Восстанавливаем оригинальные значения
            for addr, value in current_values.items():
                try:
                    self.pm.write_int(addr, value)
                except:
                    pass

            return []

        # Теперь выполним операцию в игре, которая изменит деньги
        print("\nТеперь нам нужно изменить деньги в игре естественным образом.")
        print("Пожалуйста, выполните действие в игре, которое изменит количество денег")
        print("(например, купите что-то или заработайте деньги).")
        print("После того, как деньги изменятся, введите новое значение денег:")

        try:
            new_game_money = int(input())
        except ValueError:
            print("Неверный ввод. Используем значение по умолчанию.")
            new_game_money = test_value + 10

        # Проверяем, какие адреса обновились до нового значения
        updated_addresses = []
        for addr in current_values.keys():
            try:
                new_value = self.pm.read_int(addr)
                if new_value == new_game_money:
                    updated_addresses.append(addr)
                    print(f"Адрес {hex(addr)} обновился до {new_game_money}")
            except:
                pass

        print(f"\nНайдено {len(updated_addresses)} адресов, которые обновились до нового значения денег:")
        for addr in updated_addresses:
            print(f"  {hex(addr)}")

        # Восстанавливаем исходное значение денег
        if updated_addresses:
            for addr in updated_addresses:
                try:
                    self.pm.write_int(addr, current_values[addr])
                    print(f"Восстановлено исходное значение для адреса {hex(addr)}")
                except Exception as e:
                    print(f"Ошибка при восстановлении значения для адреса {hex(addr)}: {str(e)}")

        print("Проверьте, что деньги в игре вернулись к исходному значению.")

        return updated_addresses

    # Проверка адресов и определение, какие из них действительно отвечают за деньги
    def verify_addresses(self, all_addresses, test_value):
        print("Проверка найденных адресов...")

        # Получаем уникальные адреса
        unique_addresses = list(set(all_addresses))
        print(f"Проверка {len(unique_addresses)} уникальных адресов...")

        # Сначала предлагаем автоматическую проверку
        print("\nДоступно два метода проверки адресов:")
        print("1. Автоматический метод (программа сама определит нужные адреса)")
        print("2. Ручной метод (проверка по группам)")
        verify_method = input("Выберите метод проверки (1/2): ")

        if verify_method == "1":
            return self.auto_verify_addresses(unique_addresses, test_value)

        # Если выбран ручной метод или автоматический не сработал, используем ручную проверку
        # Группируем адреса для более эффективной проверки
        address_groups = []
        for i in range(0, len(unique_addresses), 5):  # По 5 адресов в группе
            address_groups.append(unique_addresses[i:i + 5])

        # Сохраняем оригинальные значения
        original_values = {}
        for addr in unique_addresses:
            try:
                original_values[addr] = self.pm.read_int(addr)
            except:
                continue

        verified_addresses = []

        # Проверяем каждую группу адресов
        print("\nПроверка адресов по группам:")

        for i, group in enumerate(address_groups):
            # Показываем адреса группы
            print(f"\nГруппа {i + 1} из {len(address_groups)}")
            for addr in group:
                print(f"  {hex(addr)}")

            # Изменяем значения в этой группе
            for addr in group:
                if addr in original_values:
                    try:
                        self.pm.write_int(addr, test_value)
                    except:
                        continue

            print(f"Изменено значение на {test_value} для группы адресов.")
            print("Проверьте, изменилось ли количество денег в игре.")
            result = input("Изменилось ли количество денег в игре на " + str(test_value) + "? (y/n): ").lower()

            if result == 'y':
                # Нашли группу с нужными адресами, теперь проверим каждый адрес
                print("Найдена группа с нужными адресами! Проверяем каждый адрес...")

                # Сначала восстановим оригинальные значения
                for addr in group:
                    if addr in original_values:
                        try:
                            self.pm.write_int(addr, original_values[addr])
                        except:
                            continue

                # Теперь проверим каждый адрес отдельно
                for addr in group:
                    if addr in original_values:
                        try:
                            # Сохраняем оригинальное значение
                            original = original_values[addr]
                            # Изменяем значение только для этого адреса
                            self.pm.write_int(addr, test_value)

                            print(f"Адрес {hex(addr)}: изменено на {test_value}.")
                            individual_result = input("Изменились ли деньги в игре? (y/n): ").lower()

                            if individual_result == 'y':
                                verified_addresses.append(addr)

                            # Восстанавливаем оригинальное значение
                            self.pm.write_int(addr, original)

                        except Exception as e:
                            print(f"Ошибка при проверке адреса {hex(addr)}: {str(e)}")
                            continue

            # Восстанавливаем оригинальные значения для всей группы
            for addr in group:
                if addr in original_values:
                    try:
                        self.pm.write_int(addr, original_values[addr])
                    except:
                        continue

        return verified_addresses

    # Поиск адресов памяти, связанных с деньгами в игре
    def find_money_addresses(self):
        # Запрашиваем у пользователя текущее значение денег
        try:
            self.current_money = int(input("Введите текущее количество денег в игре: "))
        except ValueError:
            print("Неверный ввод. Введите число.")
            return False

        # Спрашиваем пользователя, какой метод сканирования использовать
        print("\nДоступны два метода сканирования:")
        print("1. Быстрый метод (сканирование только известных областей)")
        print("2. Полный метод (более тщательное сканирование, но медленнее)")
        scan_method = input("Выберите метод сканирования (1/2): ")

        all_addresses = []
        if scan_method == "1":
            # Быстрый метод: проверяем только известные шаблоны адресов
            all_addresses = self.scan_known_patterns(self.current_money)
        else:
            # Полный метод не реализуем, используем быстрый
            print("Полный метод в этой версии не реализован. Используем быстрый метод.")
            all_addresses = self.scan_known_patterns(self.current_money)

        if not all_addresses:
            print("Не удалось найти адреса с текущим значением денег.")
            print("Убедитесь, что вы ввели правильное значение и попробуйте снова.")
            return False

        # Запрашиваем тестовое значение для проверки адресов
        try:
            test_value = int(input("Введите тестовое значение для проверки (рекомендуется: текущее значение + 1000): "))
        except ValueError:
            print("Неверный ввод. Используем значение по умолчанию.")
            test_value = self.current_money + 1000

        # Проверяем адреса, чтобы определить, какие из них действительно связаны с деньгами
        verified_addresses = self.verify_addresses(all_addresses, test_value)

        if not verified_addresses:
            print("Не удалось найти адреса, связанные с деньгами в игре.")
            print("Попробуйте запустить программу снова.")
            return False

        # Сохраняем найденные адреса
        self.money_addresses = verified_addresses
        print(f"\nНайдено {len(verified_addresses)} адресов, связанных с деньгами в игре:")
        for addr in verified_addresses:
            print(f"  {hex(addr)}")

        # Сохраняем адреса для будущего использования
        self.save_addresses()
        return True

    # Изменение значения денег
    def change_money(self, new_value):
        if not self.money_addresses:
            print("Не найдены адреса для изменения денег.")
            return False

        successful_writes = 0
        for addr in self.money_addresses:
            try:
                self.pm.write_int(addr, new_value)
                successful_writes += 1
            except Exception as e:
                print(f"Ошибка при записи значения по адресу {hex(addr)}: {str(e)}")

        print(f"Успешно изменено {successful_writes} из {len(self.money_addresses)} адресов")

        if successful_writes > 0:
            self.current_money = new_value
            return True
        else:
            return False

    # Отслеживание изменений в памяти (мониторинг адресов)
    def monitor_memory_changes(self, duration=10):
        """
        Отслеживает изменения в памяти в течение указанного времени
        """
        print(f"\nНачинаем мониторинг изменений в памяти ({duration} секунд)...")
        print("Играйте в игру как обычно и заработайте немного денег.")
        print("Программа отслеживает, какие адреса изменяются.")

        # Определяем области памяти для мониторинга
        memory_regions = []
        patterns = ["24A1", "24AC", "24AE", "24AF"]

        for pattern in patterns:
            start_addr = int(pattern + "00000", 16)
            end_addr = int(pattern + "FFFFF", 16)
            memory_regions.append((start_addr, end_addr - start_addr))

        # Сохраняем текущие значения
        initial_values = {}
        for start_addr, size in memory_regions:
            try:
                print(f"Сканирование региона {hex(start_addr)} - {hex(start_addr + size)}")
                buffer = self.pm.read_bytes(start_addr, size)

                # Ищем все 4-байтовые значения
                for offset in range(0, size - 4, 4):
                    addr = start_addr + offset
                    try:
                        value = struct.unpack("<I", buffer[offset:offset + 4])[0]
                        if 0 <= value <= 1000000:  # Разумные значения для денег
                            initial_values[addr] = value
                    except:
                        continue

                print(f"  Сохранено {len(initial_values)} значений из этого региона")

            except Exception as e:
                print(f"  Ошибка при сканировании региона: {str(e)}")

        print(f"Всего сохранено {len(initial_values)} исходных значений.")

        # Ждем указанное время
        print(f"Мониторинг запущен. Пожалуйста, заработайте или потратьте деньги в игре.")
        for i in range(duration, 0, -1):
            print(f"\rОсталось {i} секунд... ", end="")
            time.sleep(1)
        print("\nЗавершение мониторинга...")

        # Проверяем, какие значения изменились
        changed_values = {}
        for addr, initial_value in initial_values.items():
            try:
                current_value = self.pm.read_int(addr)
                if current_value != initial_value:
                    changed_values[addr] = (initial_value, current_value)
            except:
                continue

        print(f"\nОбнаружено {len(changed_values)} измененных значений:")
        for addr, (old, new) in changed_values.items():
            print(f"  {hex(addr)}: {old} -> {new}")

        return changed_values

    # Чтение текущего значения денег
    def read_current_money(self):
        if not self.money_addresses:
            print("Не найдены адреса для чтения денег.")
            return None

        try:
            # Получаем приоритетный адрес, если он есть в списке
            priority_addr = next((addr for addr in self.money_addresses if addr in self.priority_addresses), None)

            if priority_addr:
                value = self.pm.read_int(priority_addr)
            else:
                # Иначе используем первый адрес
                value = self.pm.read_int(self.money_addresses[0])

            self.current_money = value
            return value
        except Exception as e:
            print(f"Ошибка при чтении значения: {str(e)}")
            return None

    # Закрытие соединения с процессом
    def disconnect(self):
        if self.pm:
            self.pm.close_process()
            print("Отключено от процесса игры.")


# Главная функция программы
def main():
    # Проверка прав администратора
    if not is_admin():
        print("Эта программа требует прав администратора для доступа к памяти игры.")
        print("Пожалуйста, запустите программу от имени администратора.")
        input("Нажмите Enter для выхода...")
        return

    print("=== Модификатор денег для Parcel Simulator ===")
    print("Версия 3.0 - Оптимизированная версия с расширенными возможностями")

    # Создаем экземпляр модификатора
    modifier = ParcelMoneyModifier()

    # Подключаемся к процессу игры
    if not modifier.connect_to_game():
        input("Нажмите Enter для выхода...")
        return

    # Пытаемся загрузить сохраненные адреса
    if not modifier.load_saved_addresses():
        print("Не удалось загрузить сохраненные адреса. Выполняем поиск новых адресов...")
        if not modifier.find_money_addresses():
            input("Нажмите Enter для выхода...")
            return

    # Главное меню программы
    while True:
        print("\n=== Меню ===")
        print(f"Текущее количество денег: {modifier.read_current_money()}")
        print("1. Изменить количество денег")
        print("2. Найти адреса заново")
        print("3. Мониторинг изменений в памяти (для отладки)")
        print("0. Выход")

        choice = input("Выберите действие: ")

        if choice == "1":
            try:
                new_money = int(input("Введите новое количество денег: "))
                modifier.change_money(new_money)
                print("Проверьте, изменилось ли количество денег в игре.")
            except ValueError:
                print("Неверный ввод. Введите число.")

        elif choice == "2":
            modifier.find_money_addresses()

        elif choice == "3":
            duration = input("Введите длительность мониторинга в секундах (по умолчанию 10): ")
            try:
                duration = int(duration)
            except ValueError:
                duration = 10

            modifier.monitor_memory_changes(duration)

        elif choice == "0":
            print("Закрытие программы...")
            modifier.disconnect()
            break

        else:
            print("Неверный выбор. Попробуйте снова.")


# Запуск программы
if __name__ == "__main__":
    main()