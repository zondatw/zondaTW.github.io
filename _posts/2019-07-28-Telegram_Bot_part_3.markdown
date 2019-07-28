---
layout: post
title:  "Telegram Bot - part 3"
date:   2019-07-28 15:45:00 +0800
categories: Telegram Bot
---

## 前言

前面玩過web hook了，接著來玩玩更多Telegram bot的功能  

## 開始

這次就來玩玩keyboard，用起來蠻簡單的，詳細可以參考[space](https://core.telegram.org/bots/api#inlinekeyboardmarkup)  

### Inline keyboard

```python
def send_inline_keyboard(token, chat_id, message):
    reply_markup = {
        "inline_keyboard": [[
            {
                "text": "1",
                "callback_data": 1,
            },
            {
                "text": "2",
                "callback_data": 2,
            },
            {
                "text": "3",
                "callback_data": 3,
            },
            {
                "text": "4",
                "callback_data": 4,
            },
            {
                "text": "5",
                "callback_data": 5,
            },
            {
                "text": "6",
                "callback_data": 6,
            },
            {
                "text": "7",
                "callback_data": 7,
            },
            {
                "text": "8",
                "callback_data": 8,
            },
        ],]
    }
    reply_markup = json.dumps(reply_markup)
    url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={message}&reply_markup={reply_markup}"
    response = requests.get(url)
    return response.status_code == 200, response.text
```

會出現這畫面:  
![Inline Keyboard](/assets\images\2019-07-28-Telegram_Bot_part_3\inline_keyboard.PNG)  

點擊任意按鈕後，webhook可以拿到這次事件的內容:  
![Inline Keyboard Pressed](/assets\images\2019-07-28-Telegram_Bot_part_3\inline_keyboard_pressed.PNG)  

拿取到事件後，可以在一定的時間內回覆這個事件:

```python
def answer_callback_query(token, callback_query_id, message):
    url = f"https://api.telegram.org/bot{token}/answerCallbackQuery?callback_query_id={callback_query_id}&text={message}"
    response = requests.get(url)
    return response.status_code == 200, response.text
```

比方說，不管按任意按鈕，都回覆個`I'm test`  
![answer callback query](/assets\images\2019-07-28-Telegram_Bot_part_3\answerCallback.PNG)  


### Keybaord

```python
def send_keyboard(token, chat_id, message):
    reply_markup = {
        "keyboard": [[
            {
                "text": "1",
            },
            {
                "text": "2",
            },
            {
                "text": "3",
            },
            {
                "text": "4",
            },
            {
                "text": "5",
            },
            {
                "text": "6",
            },
            {
                "text": "7",
            },
            {
                "text": "8",
            },
        ],]
    }
    reply_markup = json.dumps(reply_markup)
    url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={message}&reply_markup={reply_markup}"
    response = requests.get(url)
    return response.status_code == 200, response.text
```

會出現這畫面:  
![Keyboard](/assets\images\2019-07-28-Telegram_Bot_part_3\keyboard.PNG)  
按下任意按鈕`,會主動幫你回覆按鈕內容:  
![Keyboard pressed](/assets\images\2019-07-28-Telegram_Bot_part_3\keyboard_pressed.PNG)  
![Keyboard pressed content](/assets\images\2019-07-28-Telegram_Bot_part_3\keyboard_pressed_content.PNG)  

這就是Telegram Bot 主要的2個keyboard功能。  
Part 3 就先到這囉~  
