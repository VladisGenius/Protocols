import sys
from datetime import datetime

import requests

def print_info(info):
    '''Выводит информацию о пользователе, полученную с помощью get_user_id'''

    info = info[0]

    print()
    print(f"Имя пользователя: {info['first_name']} {info['last_name']}")
    print(f"id пользователя: {info['id']}")
    print(f"Город пользователя: {info['city']['title']}")
    print(f"Дата рождения: {info['bdate']}")
    print(f"Пол: {'Мужской' if info['sex'] == 2 else 'Женский'}")


def get_user_id(user_id, access_token):
    '''Получает информацию о пользователе с user_id, обращаясь к VK API'''

    url = "https://api.vk.com/method/users.get"
    params = {
        'fields': 'sex,bdate,city,country',
        'user_ids': user_id,
        'access_token': access_token,
        'v': '5.199'
    }

    response = requests.get(url, params=params)
    data = response.json()

    try:
        return data['response']
    except Exception as e:
        return None

def get_friends_list(user_id, access_token):
    '''Возвращает список друзей пользователя с user_id, обращаясь в VK API'''

    url = "https://api.vk.com/method/friends.get"

    params = {
        'user_id': user_id,
        'access_token': access_token,
        'v': '5.199',
        'fields': 'first_name,last_name'
    }

    try:
        response = requests.get(url, params=params)
        data = response.json()

        if 'response' in data:
            friends = data['response']['items']
            return friends
        else:
            return None

    except Exception as e:
        print("Ошибка при запросе к API:", e)
        return None


def print_friends(friends):
    '''Функция, выводящая список друзей, полученный с помощью get_friends_list'''

    if not friends:
        print("Нет данных о друзьях")
        return

    print(f"Друзей у пользователя: {len(friends)}")
    print("Список друзей:")
    print("-" * 40)

    for i, friend in enumerate(friends, 1):
        first_name = friend.get('first_name', 'Неизвестно')
        last_name = friend.get('last_name', 'Неизвестно')
        print(f"{i}. {first_name} {last_name}")


def main():
    '''Основная функция'''

    with open('vk_token.txt') as f:
        access_token = f.readline()

    user_id = sys.argv[1]

    user_info = get_user_id(user_id, access_token)

    try:
        print_info(user_info)
    except Exception as e:
        print(f"Не удалось получить информацию об ID")
        return

    if not user_id.isdigit():
        user_id = user_info[0]['id']

    friends = get_friends_list(user_id, access_token)
    print_friends(friends)



if __name__ == '__main__':
    main()