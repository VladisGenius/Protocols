import pickle
import socket
import threading
import time


class Entry:

    def __init__(self, e_type, name, data_len, e_data, expires):
        self.type = e_type
        self.len = data_len
        self.name = name
        self.data = e_data
        self.expires = expires

    def get(self):
        """Превращает запись в поток байтов для секции ответов"""

        if self.type in (1, 28):
            encoded_name = b''.join([bytes([len(part)]) + part.encode() for part in self.name.split('.')]) + b'\x00'

            # Преобразуем IP в байты
            data = bytes(map(int, self.data.split('.')))

            ttl = self.expires - time.time()
            if ttl < 0:
                return b''

            return (
                    encoded_name +  # Имя
                    (b'\x00\x01' if self.type == 1 else b'\x00\x1c') +  # Тип A (1)
                    b'\x00\x01' +  # Класс IN (1)
                    int(ttl).to_bytes(4, 'big') +  # TTL
                    int(self.len).to_bytes(2, 'big') +  # Длина данных (4 байта для IPv4)
                    data  # IP-адрес
            )

        elif self.type in (2, 12):
            encoded_name = b''.join([bytes([len(part)]) + part.encode() for part in self.name.split('.')]) + b'\x00'

            data = b''.join([bytes([len(part)]) + part.encode() for part in self.data.split('.')]) + b'\x00'

            if self.expires == 0:
                ttl = 100
            else:
                ttl = self.expires - time.time()

            if ttl < 0:
                return b''

            leng = 1
            for b in  self.data.split('.'):
                leng += len(b) + 1

            return (
                    encoded_name +  # Имя
                    (b'\x00\x02' if self.type == 2 else b'\x00\x0c') +  # Тип A (1)
                    b'\x00\x01' +  # Класс IN (1)
                    int(ttl).to_bytes(4, 'big') +  # TTL
                    int(leng).to_bytes(2, 'big') +  # Длина данных (4 байта для IPv4)
                    data  # IP-адрес
            )

class Answerer:

    @staticmethod
    def create_answer(question: bytes, entries: list[Entry]):
        """Собирает пакет ответа с entries в секции ответов"""

        answer = question[0:2] + b'\x81' +  b'\x80' + question[4:6] + len(entries).to_bytes(2, byteorder='big') + question[8:]

        for i in entries:
            answer = answer + i.get()

        return answer

    @staticmethod
    def return_empty(question: bytes):
        """Собирает пакет без ответов с кодом ошибки 3 (нет ответа)"""
        return question[0:2] + b'\x81' + b'\x83' + question[4:]

class ServerCache:

    def __init__(self):
        self.ip_to_name: dict = dict()
        self.name_to_ip: dict = dict()
        self._running = True
        self._last_clean = 0
        self._cleaner_thread = threading.Thread(target=self.clean_loop, daemon=True)
        self._cleaner_thread.start()

    def clean(self):
        """Пробегается по всем записям и удаляет старевшие"""

        print("Чистка")
        for ip in self.ip_to_name:
            for entry in self.ip_to_name[ip]:
                if entry.expires < time.time():
                    self.ip_to_name[ip].remove(entry)
                    print(f"Удалена {ip} {entry.data}")

        for name in self.name_to_ip:
            for entry in self.name_to_ip[name]:
                if entry.expires < time.time():
                    self.name_to_ip[name].remove(entry)
                    print(f"Удалена {name} {entry.data}")

    def clean_loop(self):
        """Раз в 30 секунд запускает чистку (с проверкой флага каждую секунду)"""
        while self._running:
            time.sleep(1)
            if time.time() - self._last_clean >= 30:
                self.clean()
                self._last_clean = time.time()

    def save(self, filename='dns_cache.pickle'):
        print("Сохраняем кэш...")
        self._running = False
        if self._cleaner_thread.is_alive():
            self._cleaner_thread.join(timeout=1)  # Ожидаем завершение не более 1 секунды

        try:
            with open(filename, 'wb') as f:
                pickle.dump((self.ip_to_name, self.name_to_ip), f)
            print("Кэш успешно сохранён")
        except Exception as e:
            print(f"Ошибка при сохранении кэша: {e}")

    def upload(self, filename = 'dns_cache.pickle'):
        try:
            with open(filename, 'rb') as f:
                dicts = pickle.load(f)
                self.ip_to_name = dicts[0]
                self.name_to_ip = dicts[1]

                print("Данные кэша закачаны из памяти")

                self.clean()
        except:
            self.ip_to_name = dict()
            self.name_to_ip = dict()
            print("Существующий кэш не найден")


class PackageParser:

    def __init__(self, package: bytes, cache: ServerCache):
        self._package = package
        self._message = bytearray(package)
        self._next_byte = 12
        self._cache = cache

    def recursive_read(self, index: int):
        """Считывает часть пакета, начиная с полученного индекса. Найдя ссылку, рекурсивно вызывает себя"""
        result = ""

        while True:
            length: int = int(self._message[index])

            # Конец
            if not length:
                index += 1
                break

            # Не ссылка
            elif length & 0xc0 != 0xc0:
                result += self._package[index + 1:index + 1 + length].decode('utf-8') + "."
                index += 1 + length

            # ссылка
            else:
                ref = (length * 256 + self._message[index + 1]) & 0x3fff
                result += self.recursive_read(ref)
                index += 2
                break

        return result


    def read_as_referencable(self):
        """Считывает часть пакета, начиная с полученного индекса. Найдя ссылку, вызывает recursive_read"""
        result = ""

        while True:

            length: int = int(self._message[self._next_byte])

            # Конец
            if not length:
                self._next_byte += 1
                break

            # Не ссылка
            elif length & 0xc0 != 0xc0:
                result += self._package[self._next_byte + 1:self._next_byte + 1 + length].decode('utf-8') + "."
                self._next_byte += 1 + length

            # ссылка
            else:
                ref = (length * 256 + self._message[self._next_byte + 1]) & 0x3fff

                result += self.recursive_read(ref)

                self._next_byte += 2
                break


        return result

    def get_type_and_class(self):
        req_type = self._message[self._next_byte] * 256 + self._message[self._next_byte + 1]

        self._next_byte += 2
        req_class = self._message[self._next_byte] * 256 + self._message[self._next_byte + 1]
        self._next_byte += 2

        return req_type, req_class

    def get_ttl_and_len(self):
        ans_ttl = (self._message[self._next_byte] * 256 + self._message[self._next_byte + 1]) * 256**2 + self._message[self._next_byte + 2] * 256 + self._message[self._next_byte + 3]
        self._next_byte += 4
        ans_len = self._message[self._next_byte] * 256 + self._message[self._next_byte + 1]
        self._next_byte += 2

        return ans_ttl , ans_len

    def read_as_address(self, ans_len: int):
        """Следующие ans_len байт как айпи адрес"""
        address = ""
        for j in range(ans_len):
            address += str(self._message[self._next_byte]) + "."
            self._next_byte += 1

        return address

    def get_requests(self):
        """Считывает все запросы из пакета"""


        entry_count = self._message[4] * 256 + self._message[5]

        requests = []

        for i in range(entry_count):

            current = self.read_as_referencable()

            req_type, req_class = self.get_type_and_class()

            requests.append((current[:-1], req_type))

        return requests

    def get_answers(self, count_start):
        """
        Считывает все ответы из секции, кол-во записей которой указаны в count_start и count_start + 1 байтах
        Все считанное пишет в кэш
        """
        entry_count = self._message[count_start] * 256 + self._message[count_start + 1]

        for i in range(entry_count):

            current = self.read_as_referencable()[:-1]

            req_type, req_class = self.get_type_and_class()
            ans_ttl, ans_len = self.get_ttl_and_len()

            ans = ""

            if req_type in (1, 28):
                ans = self.read_as_address(ans_len)


            elif req_type in (12, 2):
                ans = self.read_as_referencable()

            entry = Entry(req_type, current, ans_len, ans[:-1], time.time() + ans_ttl)

            if req_type in (1, 28):
                if current in cache.name_to_ip:

                    for j in cache.name_to_ip[current]:
                        if j.data == entry.data:
                            cache.name_to_ip[current].remove(j)
                            break

                    cache.name_to_ip[current].append(entry)

                else:
                    cache.name_to_ip[current] = [entry]

            elif req_type in (12, 2):
                if current in cache.ip_to_name:
                    for j in cache.ip_to_name[current]:
                        if j.data == entry.data:
                            cache.ip_to_name[current].remove(j)
                            break

                    cache.ip_to_name[current].append(entry)
                else:
                    cache.ip_to_name[current] = [entry]

        return self._next_byte

    def read_entire_answer(self):
        """Читает весь пакет, заполняя кэш"""

        self.get_requests()
        self.get_answers(6)
        self.get_answers(8)
        self.get_answers(10)



def handle(sock, data, addr, cache):
    """Решает ДНС запрос"""
    original_parser = PackageParser(data, cache)

    requests = original_parser.get_requests()
    req_count = len(requests)
    answers = []

    for req in requests:
        if req[0] == "1.0.0.127.in-addr.arpa" or "IGD_Rostelecom" in req[0]:
            sock.sendto(Answerer.return_empty(data), addr)
            return

    print(f"Запрос от {addr}.")

    for req in requests:
        if req[1] in (1, 28) and req[0] in cache.name_to_ip:
            answer = cache.name_to_ip[req[0]]

            for entry in answer:
                if entry.type == req[1]:
                    answers.append(entry)

                    if req in requests:
                        requests.remove(req)

        elif req[1] in (2, 12) and req[0] in cache.ip_to_name:
            answer = cache.ip_to_name[req[0]]

            for entry in answer:
                if entry.type == req[1]:
                    answers.append(entry)

                    if req in requests:
                        requests.remove(req)

    if req_count == len(requests):
        print("Данных в кэше нет")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.sendto(data, ('8.8.8.8', 53))

            response_data, _ = upstream.recvfrom(512)

            response_parser = PackageParser(response_data, cache)

            response_parser.read_entire_answer()
            sock.sendto(response_data, addr)
            return

    elif len(requests):
        print("Данных в кэше не хватает")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.sendto(data, ('8.8.8.8', 53))

            response_data, _ = upstream.recvfrom(512)

            response_parser = PackageParser(response_data, cache)

        response_parser.read_entire_answer()

        for req in requests:
            if req[1] in (1, 28) and req[0] in cache.name_to_ip:
                cache.clean()
                answer = cache.name_to_ip[req[0]]
                answers.append(answer)
                requests.remove(req)
            elif req[1] in (2, 12) and req[0] in cache.ip_to_name:
                cache.clean()
                answer = cache.ip_to_name[req[0]]
                answers.append(answer)
                requests.remove(req)

    else:
        print("Есть в кэше")

    sock.sendto(Answerer.create_answer(data, list(answers)), addr)

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', 53))
        print("DNS сервер запущен")
        cache = ServerCache()
        cache.upload()

        try:
            while True:
                try:
                    sock.settimeout(1)  # Уменьшаем таймаут для более быстрой реакции
                    data, addr = sock.recvfrom(512)
                    threading.Thread(target=handle, args=(sock, data, addr, cache)).start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\nПолучен сигнал завершения, сохраняем кэш...")
            cache.save()
            print("Сервер корректно остановлен")