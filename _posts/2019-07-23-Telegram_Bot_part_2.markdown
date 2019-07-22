---
layout: post
title:  "Telegram Bot - part 2"
date:   2019-07-23 01:28:00 +0800
categories: Telegram Bot
---

## 前言

前面玩過簡單的接收和發送了，接下來就來玩玩搭配web hook囉~  

## 開始

### 簡易接收

#### flask server

先來玩個簡易web hook的接收，首先寫一個flask的server  

```python
from pprint import pprint

from flask import Flask, request
from flask.views import MethodView

app = Flask(__name__)


class HookAPI(MethodView):
    def post(self):
        pprint(request.get_json(force=True))
        return "OK"


app.add_url_rule("/hook", view_func=HookAPI.as_view("hook"))

if __name__ == "__main__":
    app.run()
```

寫完後，執行他預設會開在5000 port，將資料post給[http://127.0.0.1:5000/hook](http://127.0.0.1:5000/hook)，  
在console介面上就可以看到送過來的data了。  

然後可以利用一個小工具將我們的Server部屬在外面，叫做[ngrok](https://ngrok.com/)，  
使用方法蠻簡單的，裝完後，下命令 `ngrok http 5000`，他就會產生一組domain，讓我們可以設定給Telegram bot囉~  

#### set webhook

拿到ngrok的domain後，我們來將他設定給Telegram bot，  
`https://api.telegram.org/bot{$token}/setWebhook?url={$webhook_url}`
利用這組url設定我們的web hook url，設定成功會出現下面畫面  
![set webhook](/assets\images\2019-07-23-Telegram_Bot_part_2\setwebhook.PNG)  

#### try

然後來試試送隨便一個訊息給bot，我們就會接收到  
![webhook get](/assets\images\2019-07-23-Telegram_Bot_part_2\webhook_get.PNG)  

既然現在會接收了，我們就來做個echo bot好了。  

### Echo Bot

#### echo server

```python
import requests
from flask import Flask, request
from flask.views import MethodView

app = Flask(__name__)

bot_token = "XXXXXXXXXXXXXXXXXXXXXXXXXXX"

def send_message(token, chat_id, message):
    url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={message}"
    response = requests.get(url)
    return response.status_code == 200, response.text


class HookAPI(MethodView):
    def post(self):
        json_data = request.get_json(force=True)
        send_message(bot_token, json_data["message"]["chat"]["id"], json_data["message"]["text"])
        return "OK"


app.add_url_rule("/hook", view_func=HookAPI.as_view("hook"))

if __name__ == "__main__":
    app.run()
```

完成後，我們試試傳點訊息給bot，就成功囉~  
![echo chat](/assets\images\2019-07-23-Telegram_Bot_part_2\echo_chat.PNG)  

Part 2 就先到這囉~  
