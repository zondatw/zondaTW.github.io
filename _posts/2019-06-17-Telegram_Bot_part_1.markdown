---
layout: post
title:  "Telegram Bot - part 1"
date:   2019-06-17 20:04:00 +0800
categories: Telegram Bot
---

## 前言

最近突然想玩玩Telegram的聊天機器人，所以就來玩玩看了~

## 開始

### Step 1 - 加官方Bot

加官方的一個Bot，Telegram的Bot統一由它做管理(@BotFather)  
![add_bot_father](/assets/images/2019-06-17-Telegram_Bot_part_1/add_bot_father.PNG)  
加入後會跳出:  
![start_after_add_bot](/assets/images/2019-06-17-Telegram_Bot_part_1/start_after_add_bot.PNG)  

### Step 2 - 建立新的Bot

在聊天室窗打`/newbot`，輸入對自己顯示的名稱(name)以及對外用的bot名稱(username)，注意對外的名稱要是bot結尾  
![new_bot](/assets/images/2019-06-17-Telegram_Bot_part_1/new_bot.PNG)  

### Step 3 - 對話

創建好後，就試著跟Bot對話吧，  
而跟Bot對話有個API(`https://api.telegram.org/bot{$token}/getUpdates`)，將{$token}換成你剛剛所拿到的Token就可以取得任何人跟你的Bot對話的內容囉~  
![before_talk](/assets/images/2019-06-17-Telegram_Bot_part_1/before_talk.PNG)  
![after_talk](/assets/images/2019-06-17-Telegram_Bot_part_1/after_talk.PNG)  
網頁中會有一些對話的資訊，是以json格式顯示的。  

### Step 4 - 通知使用者

可以從剛剛的json格式中拿到user id，再透過一個api去通知使用者(
`https://api.telegram.org/bot{$token}/sendMessage?chat_id={$chat_id}&text={$message}`)  
chat_id放user id的話，就能跟user對話囉~  
![bot_send_msg](/assets/images/2019-06-17-Telegram_Bot_part_1/bot_send_msg.PNG)  

Part 1 就先到這囉~  
