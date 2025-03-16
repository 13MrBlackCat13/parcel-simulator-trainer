import pymem
import struct
import time
import os
import json
import ctypes
import keyboard
import threading
import binascii
import locale
from typing import Dict, Any


# Global language settings
class Language:
    ENGLISH = 'en'
    RUSSIAN = 'ru'
    GERMAN = 'de'

    # Default language
    current = None

    # Translation dictionaries
    translations = {
        ENGLISH: {
            'title': 'Money Modifier for Parcel Simulator',
            'version': 'Version 7.1 - With Signatures and Multilanguage Support',
            'connecting': 'Connecting to the game {}...',
            'connection_success': 'Successfully connected to the game! (Process ID: {})',
            'process_not_found': 'Process {} not found.',
            'ensure_game_running': 'Make sure the game is running and try again.',
            'connection_error': 'Error connecting to the game: {}',
            'searching_money_address': 'Searching for money address in game memory...',
            'loading_from_saved': 'Trying to load saved data...',
            'loaded_addresses': 'Loaded {} saved addresses.',
            'address_value': 'Address {}: value = {}',
            'found_valid_addresses': 'Found {} valid addresses.',
            'current_money': 'Current amount of money: {}',
            'no_valid_addresses': 'None of the saved addresses are valid.',
            'using_signatures': 'Trying to use saved signatures...',
            'address_by_signature': 'Found address {} by signature {}: value = {}',
            'addresses_by_signatures': 'Successfully found {} addresses by signatures.',
            'no_addresses_signatures': 'Could not find valid addresses or signatures.',
            'load_error': 'Error loading data: {}',
            'data_saved': 'Data saved to file {}',
            'save_error': 'Error saving data: {}',
            'creating_signature': 'Creating signature for money address...',
            'signature_created': 'Signature successfully created!',
            'no_addresses_to_check': 'No addresses to check.',
            'checking_addresses': 'Checking {} addresses...',
            'checking_group': 'Checking group {}/{}',
            'current_value': 'current value = {}',
            'read_error': 'read error',
            'value_set': 'Value set to {}.',
            'check_money_changed': 'Check if the money amount changed in the game.',
            'money_changed': 'Did the money change? (y/n): ',
            'address_confirmed': 'Address {} confirmed!',
            'group_has_addresses': 'Group contains target addresses! Checking each address separately...',
            'address_set_value': 'Address {}: value set to {}.',
            'write_error': 'Error writing to address {}: {}',
            'check_complete': 'Check completed. Found {} confirmed addresses.',
            'data_loaded': 'Successfully loaded saved data.',
            'creating_signatures': 'Found addresses, but no signatures. Creating them...',
            'diff_scan_intro': '\nThe differential scanning method will be used to find the money address.',
            'diff_scan_explain': 'This method can find the address even if it changes when restarting the game.',
            'enter_current_money': 'Enter the current amount of money in the game: ',
            'invalid_input': 'Invalid input. Enter a number.',
            'first_scan': 'Performing first scan...',
            'no_int_addresses': 'No addresses with integer value found. Trying Float...',
            'no_addresses_found': 'Could not find addresses. The game may use a non-standard data format.',
            'too_many_addresses': '\nToo many addresses found. Please do the following:',
            'change_money_instruct': '1. Change the amount of money in game (earn or spend some)',
            'enter_new_value_instruct': '2. Enter the new money value',
            'enter_new_money': 'Enter the new amount of money after change: ',
            'still_many_addresses': '\nStill too many addresses. Performing change scan.',
            'change_money_please': 'Please change the amount of money in the game (earn or spend).',
            'press_enter_when_done': 'Press Enter when done...',
            'address_changed': 'Address {}: {} -> {}',
            'address_increased': 'Address {}: {} -> {} (increased)',
            'address_decreased': 'Address {}: {} -> {} (decreased)',
            'addresses_after_filter': 'Remaining {} addresses after filtering',
            'testing_addresses': '\nTesting found addresses with test value {}...',
            'finding_signatures': 'Creating signatures for found addresses...',
            'no_confirmed_addresses': 'Could not confirm money addresses.',
            'money_address_not_found': 'Money address not found. First perform a search.',
            'value_changed': 'Value successfully changed at address {}',
            'change_failed': 'Could not change value at any address.',
            'money_not_found': 'Could not find money address. The game may use a non-standard data format.',
            'admin_required': 'This program requires administrator rights to access game memory.',
            'run_as_admin': 'Please run the program as administrator.',
            'press_to_exit': 'Press Enter to exit...',
            'menu_title': '=== Menu ===',
            'change_money': '1. Change money amount',
            'find_address_again': '2. Find money address again',
            'language_menu': '3. Change language',
            'exit': '0. Exit',
            'select_action': 'Select action: ',
            'enter_new_money_amount': 'Enter new amount of money: ',
            'money_changed_success': 'Money successfully changed!',
            'change_failed': 'Failed to change money.',
            'invalid_choice': 'Invalid choice. Try again.',
            'closing': 'Closing program...',
            'disconnected': 'Disconnected from game process.',
            'select_language': 'Select language:',
            'en_lang': '1. English',
            'ru_lang': '2. Russian',
            'de_lang': '3. German',
            'language_changed': 'Language changed to {}',
            'finding_regions': 'Looking for available memory regions...',
            'regions_found': 'Found {} available memory regions',
            'starting_first_scan': 'Starting first scan for value {}...',
            'press_esc': 'Press ESC to stop scanning',
            'stop_command': '\nReceived command to stop scanning',
            'scan_progress': 'Progress: {:.1f}% | Region {}/{} | Found: {}',
            'scan_complete': '\nScan completed in {:.2f} seconds',
            'scan_found': 'Found {} addresses with value {}',
            'filtering_results': 'Filtering results for value {}...',
            'remaining_addresses': 'Remaining {} addresses with value {}',
            'no_previous_results': 'No results from previous scan',
            'filtering_by_change': 'Filtering results by value change ({})...',
            'finding_signature': 'Searching for signature in memory...',
            'signature_found': 'Found signature at address {}',
            'signature_error': 'Error processing signature: {}',
            'esc_scan_stop': 'Scanning stopped by user.',
        },
        RUSSIAN: {
            'title': 'Модификатор денег для Parcel Simulator',
            'version': 'Версия 7.1 - С сигнатурами и многоязычной поддержкой',
            'connecting': 'Подключение к игре {}...',
            'connection_success': 'Успешно подключились к игре! (ID процесса: {})',
            'process_not_found': 'Процесс {} не найден.',
            'ensure_game_running': 'Убедитесь, что игра запущена и попробуйте снова.',
            'connection_error': 'Ошибка при подключении к игре: {}',
            'searching_money_address': 'Поиск адреса денег в памяти игры...',
            'loading_from_saved': 'Пробуем загрузить сохраненные данные...',
            'loaded_addresses': 'Загружено {} сохраненных адресов.',
            'address_value': 'Адрес {}: значение = {}',
            'found_valid_addresses': 'Найдено {} действительных адресов.',
            'current_money': 'Текущее количество денег: {}',
            'no_valid_addresses': 'Ни один из сохраненных адресов не действителен.',
            'using_signatures': 'Пробуем использовать сохраненные сигнатуры...',
            'address_by_signature': 'Найден адрес {} по сигнатуре {}: значение = {}',
            'addresses_by_signatures': 'Успешно найдено {} адресов по сигнатурам.',
            'no_addresses_signatures': 'Не удалось найти действующие адреса или сигнатуры.',
            'load_error': 'Ошибка при загрузке данных: {}',
            'data_saved': 'Данные сохранены в файл {}',
            'save_error': 'Ошибка при сохранении данных: {}',
            'creating_signature': 'Создание сигнатуры для адреса денег...',
            'signature_created': 'Сигнатура успешно создана!',
            'no_addresses_to_check': 'Нет адресов для проверки.',
            'checking_addresses': 'Проверка {} адресов...',
            'checking_group': 'Проверка группы {}/{}',
            'current_value': 'текущее значение = {}',
            'read_error': 'ошибка чтения',
            'value_set': 'Установлено значение {}.',
            'check_money_changed': 'Проверьте, изменилось ли количество денег в игре.',
            'money_changed': 'Деньги изменились? (y/n): ',
            'address_confirmed': 'Адрес {} подтвержден!',
            'group_has_addresses': 'Группа содержит нужные адреса! Проверяем каждый адрес отдельно...',
            'address_set_value': 'Адрес {}: установлено значение {}.',
            'write_error': 'Ошибка при записи в адрес {}: {}',
            'check_complete': 'Проверка завершена. Найдено {} подтвержденных адресов.',
            'data_loaded': 'Успешно загружены сохраненные данные.',
            'creating_signatures': 'Найдены адреса, но нет сигнатур. Создаем их...',
            'diff_scan_intro': '\nДля поиска адреса денег будет использован метод дифференциального сканирования.',
            'diff_scan_explain': 'Этот метод позволяет найти адрес, даже если он меняется при перезапуске игры.',
            'enter_current_money': 'Введите текущее количество денег в игре: ',
            'invalid_input': 'Неверный ввод. Введите число.',
            'first_scan': 'Выполняем первое сканирование...',
            'no_int_addresses': 'Не найдено адресов с целочисленным значением. Пробуем Float...',
            'no_addresses_found': 'Не удалось найти адреса. Возможно, игра использует нестандартный формат данных.',
            'too_many_addresses': '\nНайдено слишком много адресов. Выполните следующие действия:',
            'change_money_instruct': '1. Измените количество денег в игре (заработайте или потратьте немного)',
            'enter_new_value_instruct': '2. Введите новое значение денег',
            'enter_new_money': 'Введите новое количество денег после изменения: ',
            'still_many_addresses': '\nВсё еще много адресов. Выполним сканирование по изменению.',
            'change_money_please': 'Пожалуйста, измените значение денег в игре (заработайте или потратьте).',
            'press_enter_when_done': 'Нажмите Enter, когда изменение будет выполнено...',
            'address_changed': 'Адрес {}: {} -> {}',
            'address_increased': 'Адрес {}: {} -> {} (увеличилось)',
            'address_decreased': 'Адрес {}: {} -> {} (уменьшилось)',
            'addresses_after_filter': 'Осталось {} адресов после фильтрации',
            'testing_addresses': '\nПроверка найденных адресов с тестовым значением {}...',
            'finding_signatures': 'Создание сигнатур для найденных адресов...',
            'no_confirmed_addresses': 'Не удалось подтвердить адреса денег.',
            'money_address_not_found': 'Адрес денег не найден. Сначала выполните поиск.',
            'value_changed': 'Значение успешно изменено по адресу {}',
            'change_failed': 'Не удалось изменить значение ни по одному адресу.',
            'money_not_found': 'Не удалось найти адрес денег. Возможно, игра использует нестандартный формат данных.',
            'admin_required': 'Эта программа требует прав администратора для доступа к памяти игры.',
            'run_as_admin': 'Пожалуйста, запустите программу от имени администратора.',
            'press_to_exit': 'Нажмите Enter для выхода...',
            'menu_title': '=== Меню ===',
            'change_money': '1. Изменить количество денег',
            'find_address_again': '2. Найти адрес денег заново',
            'language_menu': '3. Изменить язык',
            'exit': '0. Выход',
            'select_action': 'Выберите действие: ',
            'enter_new_money_amount': 'Введите новое количество денег: ',
            'money_changed_success': 'Деньги успешно изменены!',
            'change_failed': 'Не удалось изменить деньги.',
            'invalid_choice': 'Неверный выбор. Попробуйте снова.',
            'closing': 'Закрытие программы...',
            'disconnected': 'Отключено от процесса игры.',
            'select_language': 'Выберите язык:',
            'en_lang': '1. Английский',
            'ru_lang': '2. Русский',
            'de_lang': '3. Немецкий',
            'language_changed': 'Язык изменен на {}',
            'finding_regions': 'Поиск доступных регионов памяти...',
            'regions_found': 'Найдено {} доступных регионов памяти',
            'starting_first_scan': 'Начинаем первое сканирование для значения {}...',
            'press_esc': 'Нажмите ESC для остановки сканирования',
            'stop_command': '\nПолучена команда на остановку сканирования',
            'scan_progress': 'Прогресс: {:.1f}% | Регион {}/{} | Найдено: {}',
            'scan_complete': '\nСканирование завершено за {:.2f} секунд',
            'scan_found': 'Найдено {} адресов со значением {}',
            'filtering_results': 'Фильтрация результатов для значения {}...',
            'remaining_addresses': 'Осталось {} адресов со значением {}',
            'no_previous_results': 'Нет результатов предыдущего сканирования',
            'filtering_by_change': 'Фильтрация результатов по изменению значения ({})...',
            'finding_signature': 'Поиск сигнатуры в памяти...',
            'signature_found': 'Найдена сигнатура по адресу {}',
            'signature_error': 'Ошибка при обработке сигнатуры: {}',
            'esc_scan_stop': 'Сканирование остановлено пользователем.',
        },
        GERMAN: {
            'title': 'Geldmodifikator für Parcel Simulator',
            'version': 'Version 7.1 - Mit Signaturen und mehrsprachiger Unterstützung',
            'connecting': 'Verbindung zum Spiel {} wird hergestellt...',
            'connection_success': 'Erfolgreich mit dem Spiel verbunden! (Prozess-ID: {})',
            'process_not_found': 'Prozess {} nicht gefunden.',
            'ensure_game_running': 'Stellen Sie sicher, dass das Spiel läuft, und versuchen Sie es erneut.',
            'connection_error': 'Fehler beim Verbinden mit dem Spiel: {}',
            'searching_money_address': 'Suche nach Geldadresse im Spielspeicher...',
            'loading_from_saved': 'Versuche, gespeicherte Daten zu laden...',
            'loaded_addresses': '{} gespeicherte Adressen geladen.',
            'address_value': 'Adresse {}: Wert = {}',
            'found_valid_addresses': '{} gültige Adressen gefunden.',
            'current_money': 'Aktueller Geldbetrag: {}',
            'no_valid_addresses': 'Keine der gespeicherten Adressen ist gültig.',
            'using_signatures': 'Versuche, gespeicherte Signaturen zu verwenden...',
            'address_by_signature': 'Adresse {} durch Signatur {} gefunden: Wert = {}',
            'addresses_by_signatures': 'Erfolgreich {} Adressen anhand von Signaturen gefunden.',
            'no_addresses_signatures': 'Es konnten keine gültigen Adressen oder Signaturen gefunden werden.',
            'load_error': 'Fehler beim Laden von Daten: {}',
            'data_saved': 'Daten in Datei {} gespeichert',
            'save_error': 'Fehler beim Speichern der Daten: {}',
            'creating_signature': 'Erstelle Signatur für Geldadresse...',
            'signature_created': 'Signatur erfolgreich erstellt!',
            'no_addresses_to_check': 'Keine Adressen zu überprüfen.',
            'checking_addresses': 'Überprüfe {} Adressen...',
            'checking_group': 'Überprüfe Gruppe {}/{}',
            'current_value': 'aktueller Wert = {}',
            'read_error': 'Lesefehler',
            'value_set': 'Wert auf {} gesetzt.',
            'check_money_changed': 'Prüfen Sie, ob sich der Geldbetrag im Spiel geändert hat.',
            'money_changed': 'Hat sich das Geld geändert? (y/n): ',
            'address_confirmed': 'Adresse {} bestätigt!',
            'group_has_addresses': 'Gruppe enthält Zieladressen! Überprüfe jede Adresse einzeln...',
            'address_set_value': 'Adresse {}: Wert auf {} gesetzt.',
            'write_error': 'Fehler beim Schreiben an Adresse {}: {}',
            'check_complete': 'Überprüfung abgeschlossen. {} bestätigte Adressen gefunden.',
            'data_loaded': 'Gespeicherte Daten erfolgreich geladen.',
            'creating_signatures': 'Adressen gefunden, aber keine Signaturen. Erstelle sie...',
            'diff_scan_intro': '\nDie Differenzial-Scan-Methode wird verwendet, um die Geldadresse zu finden.',
            'diff_scan_explain': 'Diese Methode kann die Adresse finden, auch wenn sie sich beim Neustart des Spiels ändert.',
            'enter_current_money': 'Geben Sie den aktuellen Geldbetrag im Spiel ein: ',
            'invalid_input': 'Ungültige Eingabe. Geben Sie eine Zahl ein.',
            'first_scan': 'Führe ersten Scan durch...',
            'no_int_addresses': 'Keine Adressen mit ganzzahligem Wert gefunden. Versuche Float...',
            'no_addresses_found': 'Keine Adressen gefunden. Das Spiel verwendet möglicherweise ein nicht standardmäßiges Datenformat.',
            'too_many_addresses': '\nZu viele Adressen gefunden. Bitte führen Sie folgende Schritte aus:',
            'change_money_instruct': '1. Ändern Sie den Geldbetrag im Spiel (verdienen oder geben Sie etwas aus)',
            'enter_new_value_instruct': '2. Geben Sie den neuen Geldwert ein',
            'enter_new_money': 'Geben Sie den neuen Geldbetrag nach der Änderung ein: ',
            'still_many_addresses': '\nImmer noch zu viele Adressen. Führe einen Änderungsscan durch.',
            'change_money_please': 'Bitte ändern Sie den Geldbetrag im Spiel (verdienen oder ausgeben).',
            'press_enter_when_done': 'Drücken Sie Enter, wenn Sie fertig sind...',
            'address_changed': 'Adresse {}: {} -> {}',
            'address_increased': 'Adresse {}: {} -> {} (erhöht)',
            'address_decreased': 'Adresse {}: {} -> {} (verringert)',
            'addresses_after_filter': 'Verbleibende {} Adressen nach Filterung',
            'testing_addresses': '\nTeste gefundene Adressen mit Testwert {}...',
            'finding_signatures': 'Erstelle Signaturen für gefundene Adressen...',
            'no_confirmed_addresses': 'Konnte keine Geldadressen bestätigen.',
            'money_address_not_found': 'Geldadresse nicht gefunden. Führen Sie zuerst eine Suche durch.',
            'value_changed': 'Wert erfolgreich an Adresse {} geändert',
            'change_failed': 'Konnte den Wert an keiner Adresse ändern.',
            'money_not_found': 'Konnte Geldadresse nicht finden. Das Spiel verwendet möglicherweise ein nicht standardmäßiges Datenformat.',
            'admin_required': 'Dieses Programm benötigt Administratorrechte, um auf den Spielspeicher zuzugreifen.',
            'run_as_admin': 'Bitte führen Sie das Programm als Administrator aus.',
            'press_to_exit': 'Drücken Sie Enter zum Beenden...',
            'menu_title': '=== Menü ===',
            'change_money': '1. Geldbetrag ändern',
            'find_address_again': '2. Geldadresse erneut suchen',
            'language_menu': '3. Sprache ändern',
            'exit': '0. Beenden',
            'select_action': 'Aktion auswählen: ',
            'enter_new_money_amount': 'Neuen Geldbetrag eingeben: ',
            'money_changed_success': 'Geld erfolgreich geändert!',
            'change_failed': 'Geldänderung fehlgeschlagen.',
            'invalid_choice': 'Ungültige Auswahl. Versuchen Sie es erneut.',
            'closing': 'Programm wird geschlossen...',
            'disconnected': 'Verbindung zum Spielprozess getrennt.',
            'select_language': 'Sprache auswählen:',
            'en_lang': '1. Englisch',
            'ru_lang': '2. Russisch',
            'de_lang': '3. Deutsch',
            'language_changed': 'Sprache auf {} geändert',
            'finding_regions': 'Suche nach verfügbaren Speicherbereichen...',
            'regions_found': '{} verfügbare Speicherbereiche gefunden',
            'starting_first_scan': 'Starte ersten Scan für Wert {}...',
            'press_esc': 'Drücken Sie ESC, um den Scan zu beenden',
            'stop_command': '\nBefehl zum Stoppen des Scans erhalten',
            'scan_progress': 'Fortschritt: {:.1f}% | Region {}/{} | Gefunden: {}',
            'scan_complete': '\nScan in {:.2f} Sekunden abgeschlossen',
            'scan_found': '{} Adressen mit Wert {} gefunden',
            'filtering_results': 'Filtere Ergebnisse für Wert {}...',
            'remaining_addresses': 'Verbleibende {} Adressen mit Wert {}',
            'no_previous_results': 'Keine Ergebnisse vom vorherigen Scan',
            'filtering_by_change': 'Filtere Ergebnisse nach Wertänderung ({})...',
            'finding_signature': 'Suche nach Signatur im Speicher...',
            'signature_found': 'Signatur an Adresse {} gefunden',
            'signature_error': 'Fehler bei der Verarbeitung der Signatur: {}',
            'esc_scan_stop': 'Scannen wurde vom Benutzer gestoppt.',
        }
    }

    @classmethod
    def get_system_language(cls):
        """Detect system language and return the closest supported language"""
        try:
            system_locale = locale.getdefaultlocale()[0].lower()
            if system_locale.startswith('ru'):
                return cls.RUSSIAN
            elif system_locale.startswith('de'):
                return cls.GERMAN
            else:
                return cls.ENGLISH
        except:
            return cls.ENGLISH

    @classmethod
    def initialize(cls):
        """Initialize language settings"""
        cls.current = cls.get_system_language()

    @classmethod
    def set_language(cls, lang_code):
        """Set current language"""
        if lang_code in [cls.ENGLISH, cls.RUSSIAN, cls.GERMAN]:
            cls.current = lang_code

    @classmethod
    def get(cls, key, *args):
        """Get translated string by key with optional formatting"""
        if cls.current is None:
            cls.initialize()

        # Get the string from the current language or fallback to English
        text = cls.translations.get(cls.current, {}).get(key)
        if text is None:
            text = cls.translations.get(cls.ENGLISH, {}).get(key, key)

        # Apply formatting if args are provided
        if args:
            return text.format(*args)
        return text


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
            print(Language.get('signature_error', str(e)))
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
            print(Language.get('signature_error', str(e)))
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

        print(Language.get('finding_signature'))

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
                    print(Language.get('signature_found', hex(result_addr)))
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

        print(Language.get('finding_regions'))

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
        print(Language.get('regions_found', len(regions)))

    # Первое сканирование - поиск значения
    def first_scan(self, value, data_type=MemoryDataType.INT32):
        if not self.memory_regions:
            self.get_memory_regions()

        size = MemoryDataType.get_size(data_type)
        value_bytes = MemoryDataType.pack_value(value, data_type)

        print(Language.get('starting_first_scan', value))

        # Создаем поток для обработки нажатия ESC
        self.stop_scan = False

        def check_for_esc():
            print(Language.get('press_esc'))
            while True:
                if keyboard.is_pressed('esc'):
                    print(Language.get('stop_command'))
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
                print(Language.get('esc_scan_stop'))
                break

            try:
                # Показываем прогресс
                if i % 10 == 0:
                    elapsed = time.time() - start_time
                    progress = (i / len(self.memory_regions)) * 100
                    print(Language.get('scan_progress', progress, i + 1, len(self.memory_regions), len(addresses)),
                          end="\r")

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
        print(Language.get('scan_complete', elapsed))
        print(Language.get('scan_found', len(addresses), value))

        self.scan_results = addresses
        return addresses

    # Следующее сканирование - фильтрация результатов
    def next_scan(self, value, data_type=MemoryDataType.INT32):
        if not self.scan_results:
            print(Language.get('no_previous_results'))
            return []

        print(Language.get('filtering_results', value))

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

        print(Language.get('remaining_addresses', len(matching_addresses), value))

        self.scan_results = matching_addresses
        return matching_addresses

    # Сканирование с учетом изменений
    def changed_value_scan(self, change_type="changed"):
        if not self.scan_results:
            print(Language.get('no_previous_results'))
            return []

        print(Language.get('filtering_by_change', change_type))

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
        print(Language.get('change_money_please'))
        input(Language.get('press_enter_when_done'))

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
                    print(Language.get('address_changed', hex(addr), old_value, new_value))
                elif change_type == "increased" and new_value > old_value:
                    matching_addresses.append(addr)
                    print(Language.get('address_increased', hex(addr), old_value, new_value))
                elif change_type == "decreased" and new_value < old_value:
                    matching_addresses.append(addr)
                    print(Language.get('address_decreased', hex(addr), old_value, new_value))
            except Exception as e:
                # Пропускаем ошибки чтения памяти
                continue

        print(Language.get('addresses_after_filter', len(matching_addresses)))

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
            print(Language.get('connecting', self.display_name))
            self.pm = pymem.Pymem(self.process_name)
            self.process_handle = self.pm.process_handle
            print(Language.get('connection_success', self.pm.process_id))

            # Создаем сканеры
            self.scanner = DifferentialMemoryScanner(self.process_handle)
            self.signature_scanner = SignatureScanner(self.process_handle)

            return True
        except pymem.exception.ProcessNotFound:
            print(Language.get('process_not_found', self.process_name))
            print(Language.get('ensure_game_running'))
            return False
        except Exception as e:
            print(Language.get('connection_error', str(e)))
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
                    print(Language.get('loaded_addresses', len(addresses)))

                    # Проверяем валидность адресов
                    valid_addresses = []
                    for addr in addresses:
                        try:
                            value = self.pm.read_int(addr)
                            if 0 <= value <= 10000000:  # Разумный диапазон для денег
                                valid_addresses.append(addr)
                                print(Language.get('address_value', hex(addr), value))
                        except:
                            continue

                    if valid_addresses:
                        self.money_addresses = valid_addresses
                        print(Language.get('found_valid_addresses', len(valid_addresses)))

                        # Считываем текущее значение денег
                        try:
                            self.current_money = self.pm.read_int(valid_addresses[0])
                            print(Language.get('current_money', self.current_money))
                        except:
                            pass

                        return True

                # Пробуем использовать сигнатуры
                if 'signatures' in data and not self.money_addresses:
                    print(Language.get('using_signatures'))
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
                                    print(Language.get('address_by_signature', hex(addr), i + 1, value))
                            except:
                                pass

                    if self.money_addresses:
                        print(Language.get('addresses_by_signatures', len(self.money_addresses)))
                        return True

            print(Language.get('no_addresses_signatures'))
            return False

        except Exception as e:
            print(Language.get('load_error', str(e)))
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

            print(Language.get('data_saved', self.save_file))
        except Exception as e:
            print(Language.get('save_error', str(e)))

    # Создание сигнатур
    def create_signature(self, address):
        # Создаем сигнатуру
        print(Language.get('creating_signature'))
        signature = self.signature_scanner.create_signature(address)
        if signature:
            self.signatures.append(signature)
            print(Language.get('signature_created'))

        # Сохраняем данные
        self.save_data()

    # Проверка адресов путем изменения значения
    def verify_addresses(self, addresses, test_value):
        if not addresses:
            print(Language.get('no_addresses_to_check'))
            return []

        # Группируем адреса для проверки (если их много)
        grouped_addresses = []
        for i in range(0, len(addresses), 5):
            grouped_addresses.append(addresses[i:i + 5])

        # Если адресов немного, проверяем каждый отдельно
        if len(addresses) <= 5:
            grouped_addresses = [[addr] for addr in addresses]

        print(Language.get('checking_addresses', len(addresses)))

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
            print(f"\n{Language.get('checking_group', i + 1, len(grouped_addresses))}")

            # Выводим адреса группы
            for addr in group:
                try:
                    current_value = self.pm.read_int(addr)
                    print(f"  {hex(addr)}: {Language.get('current_value', current_value)}")
                except:
                    print(f"  {hex(addr)}: {Language.get('read_error')}")

            # Изменяем значения всех адресов в группе
            for addr in group:
                try:
                    if addr in original_values:
                        self.pm.write_int(addr, test_value)
                except Exception as e:
                    print(Language.get('write_error', hex(addr), str(e)))

            print(Language.get('value_set', test_value))
            print(Language.get('check_money_changed'))

            # Спрашиваем пользователя, изменились ли деньги
            response = input(Language.get('money_changed')).lower()

            if response == 'y':
                # Если группа содержит только один адрес, просто добавляем его
                if len(group) == 1:
                    verified_addresses.append(group[0])
                    print(Language.get('address_confirmed', hex(group[0])))
                else:
                    # Проверяем каждый адрес в группе отдельно
                    print(Language.get('group_has_addresses'))

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

                            print(Language.get('address_set_value', hex(addr), test_value))
                            print(Language.get('check_money_changed'))

                            resp = input(Language.get('money_changed')).lower()
                            if resp == 'y':
                                verified_addresses.append(addr)
                                print(Language.get('address_confirmed', hex(addr)))

                            # Восстанавливаем значение
                            self.pm.write_int(addr, orig_value)

                        except Exception as e:
                            print(Language.get('write_error', hex(addr), str(e)))

            # Восстанавливаем оригинальные значения для всей группы
            for addr in group:
                if addr in original_values:
                    try:
                        self.pm.write_int(addr, original_values[addr])
                    except:
                        continue

        print(f"\n{Language.get('check_complete', len(verified_addresses))}")
        return verified_addresses

    # Поиск адреса денег
    def find_money_address(self):
        print(Language.get('searching_money_address'))

        # Сначала пробуем загрузить сохраненные данные
        if self.load_saved_data():
            print(Language.get('data_loaded'))

            # Если найдены адреса, но нет сигнатур, создаем их
            if self.money_addresses and not self.signatures:
                print(Language.get('creating_signatures'))
                self.create_signature(self.money_addresses[0])

            return True

        print(Language.get('diff_scan_intro'))
        print(Language.get('diff_scan_explain'))

        # Спрашиваем текущее значение денег
        try:
            current_money = int(input(Language.get('enter_current_money')))
        except ValueError:
            print(Language.get('invalid_input'))
            return False

        # Выполняем первое сканирование
        print(Language.get('first_scan'))
        self.scanner.first_scan(current_money)

        if not self.scanner.scan_results:
            # Пробуем другие типы данных
            print(Language.get('no_int_addresses'))
            self.scanner.first_scan(current_money, MemoryDataType.FLOAT)

        if not self.scanner.scan_results:
            print(Language.get('no_addresses_found'))
            return False

        # Если найдено слишком много адресов, фильтруем их с помощью дифференциального сканирования
        if len(self.scanner.scan_results) > 100:
            print(Language.get('too_many_addresses'))
            print(Language.get('change_money_instruct'))
            print(Language.get('enter_new_value_instruct'))

            try:
                new_money = int(input(Language.get('enter_new_money')))
            except ValueError:
                print(Language.get('invalid_input'))
                return False

            # Фильтруем результаты по новому значению
            self.scanner.next_scan(new_money)

        # Если всё еще много адресов, используем сканирование по изменению
        if len(self.scanner.scan_results) > 20:
            print(Language.get('still_many_addresses'))
            self.scanner.changed_value_scan()

        # Проверяем найденные адреса
        if self.scanner.scan_results:
            test_value = current_money + 1000
            print(Language.get('testing_addresses', test_value))

            verified_addresses = self.verify_addresses(self.scanner.scan_results, test_value)

            if verified_addresses:
                self.money_addresses = verified_addresses
                self.current_money = current_money

                # Создаем сигнатуры для найденных адресов
                if verified_addresses:
                    self.create_signature(verified_addresses[0])

                return True

        print(Language.get('no_confirmed_addresses'))
        return False

    # Изменение значения денег
    def change_money(self, new_value):
        if not self.money_addresses:
            print(Language.get('money_address_not_found'))
            return False

        success = False
        for addr in self.money_addresses:
            try:
                self.pm.write_int(addr, new_value)
                print(Language.get('value_changed', hex(addr)))
                success = True
            except Exception as e:
                print(Language.get('write_error', hex(addr), str(e)))

        if success:
            self.current_money = new_value
            return True
        else:
            print(Language.get('change_failed'))
            return False

    # Закрытие соединения с процессом
    def disconnect(self):
        if self.pm:
            self.pm.close_process()
            print(Language.get('disconnected'))


# Функция для изменения языка
def change_language():
    print(Language.get('select_language'))
    print(Language.get('en_lang'))
    print(Language.get('ru_lang'))
    print(Language.get('de_lang'))
    choice = input(Language.get('select_action'))

    if choice == '1':
        Language.set_language(Language.ENGLISH)
        print(Language.get('language_changed', 'English'))
    elif choice == '2':
        Language.set_language(Language.RUSSIAN)
        print(Language.get('language_changed', 'Русский'))
    elif choice == '3':
        Language.set_language(Language.GERMAN)
        print(Language.get('language_changed', 'Deutsch'))
    else:
        print(Language.get('invalid_choice'))


# Основная функция
def main():
    # Инициализация языка
    Language.initialize()

    # Проверка прав администратора
    if not is_admin():
        print(Language.get('admin_required'))
        print(Language.get('run_as_admin'))
        input(Language.get('press_to_exit'))
        return

    print(f"=== {Language.get('title')} ===")
    print(Language.get('version'))

    # Создаем экземпляр модификатора
    changer = MoneyChanger()

    # Подключаемся к процессу игры
    if not changer.connect_to_game():
        input(Language.get('press_to_exit'))
        return

    # Ищем адрес денег
    if not changer.find_money_address():
        print(Language.get('money_not_found'))
        input(Language.get('press_to_exit'))
        return

    # Главное меню программы
    while True:
        print(f"\n{Language.get('menu_title')}")
        print(f"{Language.get('current_money', changer.current_money)}")
        print(Language.get('change_money'))
        print(Language.get('find_address_again'))
        print(Language.get('language_menu'))
        print(Language.get('exit'))

        choice = input(Language.get('select_action'))

        if choice == "1":
            try:
                new_money = int(input(Language.get('enter_new_money_amount')))
                if changer.change_money(new_money):
                    print(Language.get('money_changed_success'))
                else:
                    print(Language.get('change_failed'))
            except ValueError:
                print(Language.get('invalid_input'))

        elif choice == "2":
            changer.find_money_address()

        elif choice == "3":
            change_language()

        elif choice == "0":
            print(Language.get('closing'))
            changer.disconnect()
            break

        else:
            print(Language.get('invalid_choice'))


# Запуск программы
if __name__ == "__main__":
    main()