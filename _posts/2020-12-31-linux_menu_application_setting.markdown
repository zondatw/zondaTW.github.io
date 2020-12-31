---
layout: post
title:  "Linux menu application setting"
date:   2020-12-31 11:43:00 +0800
categories: Linux,Gentoo
---

# 前言

現在主要的Linux是使用Gentoo，目前還是有很多軟體沒包在emerge中，
所以有時候需要下載binary檔下來用，但有時又想在KDE的menu中可以看到它，
所以就要自行設定。

## 開始

`以下用VS Code來當作範例`  

首先確認真的沒辦法直接裝  

```shell
$ emerge --search vscode

[ Results for search key : vscode ]
Searching...

[ Applications found : 0 ]

```
真的沒包在裡面QQ  

接著到官網下載Linux 的tar.gz包 [official downalod](https://code.visualstudio.com/download)  
下載好後就來解壓縮它`$ tar zxvf code-stable-x64-1608137260.tar.gz`  
解開後就會拿到一個`VSCode-linux-x64`的資料夾，  
接著將它移到你常放application的資料夾中，我是放在`/usr/local`  

接著準備要寫設定囉，  
在`/usr/share/applications`中建立一個`VSCode.desktop`的檔案，

PS:  
Application為global放在`/usr/share/applications/`  
Application為personal放在`/home/$USER/.local/share/applications/`   

內容為：

```desktop
[Desktop.Entry]
Name=Visual.Studio.Code
Comment=Multi-platform.code.editor.for.linux
Exec=/usr/local/VSCode-linux-x64/code
Icon=/usr/local/VSCode-linux-x64/resources/app/resources/linux/code.png
Type=Application
Categories=TextEditor;Development;Utility;
```

Name: Application名稱  
Comment: Application的註解  
Exec: 執行檔路徑  
Icon: Icon路徑  
Type: 在Menu中的類別  
Categories: 分類  

設定完後就可以在menu中看到VScode囉  
沒看到的話先登出再登入看看  
![menu](/assets/images/2020-12-31-linux_menu_application_setting/menu.PNG)  


Reference:  
[Archlinux-wiki Desktop entries](https://wiki.archlinux.org/index.php/desktop_entries)
