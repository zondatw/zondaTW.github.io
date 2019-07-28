---
layout: post
title:  "Telegram Bot - part 4"
date:   2019-07-28 23:04:00 +0800
categories: Telegram Bot
---

## 前言

繼續來玩玩更多Telegram bot的功能吧  

## 開始

### Force reply

這功能就是強迫人家回覆，但也是可以不用回拉，哈哈哈  

```python
def force_reply(token, chat_id, message):
    reply_markup = {
        "force_reply": True,
        "selective": False,
    }
    reply_markup = json.dumps(reply_markup)
    url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={message}&reply_markup={reply_markup}"
    response = requests.get(url)
    return response.status_code == 200, response.text
```

![Force Reply](/assets\images\2019-07-28-Telegram_Bot_part_4\froce_reply.PNG)  

### Edit Message Test

這功能是可以去修改某次發言的內容  

```python
def edit_message_test(token, chat_id, message_id, message):
    url = f"https://api.telegram.org/bot{token}/editMessageText?chat_id={chat_id}&message_id={message_id}&text={message}"
    response = requests.get(url)
    return response.status_code == 200, response.text
```

## Project

運用之前所學的功能，來寫個剪刀石頭布的遊戲吧!  

flask server

```python
import random
from pprint import pprint

import requests
from flask import Flask, request
from flask.views import MethodView

import Telegram_bot
import setting

app = Flask(__name__)

def message_service(json_data):
    if json_data["message"]["text"] == "/Game":
        Telegram_bot.play_paper_scissors_stone(setting.bot_token, json_data["message"]["chat"]["id"], "來猜拳")


def callback_query_service(json_data):
    Telegram_bot.edit_message_test(
        setting.bot_token, json_data["callback_query"]["message"]["chat"]["id"],
        json_data["callback_query"]["message"]["message_id"],
        get_result_message(json_data["callback_query"]["data"]))


def bot_rand_gesture():
    return random.choice(Telegram_bot.Gesture.list())


def get_result_message(client_gesture):
    bot_gesture = random.choice(Telegram_bot.Gesture.list())
    client_gesture_number = Telegram_bot.Gesture.get_number(client_gesture)
    bot_gesture_number = Telegram_bot.Gesture.get_number(bot_gesture)
    if client_gesture_number == bot_gesture_number:
        result_msg = "平手"
    elif ((bot_gesture_number - client_gesture_number) % 3) == 1:
        result_msg = "Bot贏了"
    else:
        result_msg = "你贏了"
    return f"你出{Telegram_bot.Gesture[client_gesture].value}， Bot出{Telegram_bot.Gesture[bot_gesture].value}， 所以{result_msg}!"


class HookAPI(MethodView):
    def post(self):
        json_data = request.get_json(force=True)
        pprint(json_data)
        if "message" in json_data:
            message_service(json_data)
        elif "callback_query" in json_data:
            callback_query_service(json_data)
        return "OK"


app.add_url_rule("/hook", view_func=HookAPI.as_view("hook"))

if __name__ == "__main__":
    app.run()
```

Telegram_bot

```python
import json
from enum import Enum

import requests

def send_message(token, chat_id, message):
    url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={message}"
    response = requests.get(url)
    return response.status_code == 200, response.text


class Gesture(Enum):
    Paper = "✋"
    Scissors = "✌️"
    Stone = "👊"

    @staticmethod
    def list():
        return list(map(lambda g: g.name, Gesture))

    @staticmethod
    def get_number(gesture):
        if gesture == Gesture.Paper.name:
            return 0
        elif gesture == Gesture.Scissors.name:
            return 1
        elif gesture == Gesture.Stone.name:
            return 2


def play_paper_scissors_stone(token, chat_id, message):
    reply_markup = {
        "inline_keyboard": [[
            {
                "text": Gesture.Paper.value,
                "callback_data": Gesture.Paper.name,
            },
            {
                "text": Gesture.Scissors.value,
                "callback_data": Gesture.Scissors.name,
            },
            {
                "text": Gesture.Stone.value,
                "callback_data": Gesture.Stone.name,
            },
        ],]
    }
    reply_markup = json.dumps(reply_markup)
    url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={message}&reply_markup={reply_markup}"
    response = requests.get(url)
    return response.status_code == 200, response.text


def edit_message_test(token, chat_id, message_id, message):
    url = f"https://api.telegram.org/bot{token}/editMessageText?chat_id={chat_id}&message_id={message_id}&text={message}"
    response = requests.get(url)
    return response.status_code == 200, response.text
```

![Game start](/assets\images\2019-07-28-Telegram_Bot_part_4\Game_start.PNG)  
![Game result](/assets\images\2019-07-28-Telegram_Bot_part_4\Game_result.PNG)  
