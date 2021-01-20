---
layout: post
title:  "Try GitLab"
date:   2021-01-20 14:57:00 +0800
categories: GitLab
---

## 前言

以前玩過拉，只是最近在玩jenkins，想用自己的環境來架，所以又再來架囉，順便紀錄一下，怕老了忘記。  

## Setup

用docker來架最方便了～  

Reference form [official doc](https://docs.gitlab.com/omnibus/docker/)  

```shell
$ docker run --detach \
  --hostname gitlab.example.com \
  --publish 443:443 --publish 80:80 --publish 22:22 \
  --name gitlab \
  --restart always \
  --volume /data/config:/etc/gitlab \
  --volume /data/logs:/var/log/gitlab \
  --volume /data/data:/var/opt/gitlab \
  gitlab/gitlab-ee:latest
```

接著連上[http://localhost](http://localhost)  
![](/assets/images/2021-01-20-try_gitlab/set_first_password.PNG)  
用剛剛的密碼登入，帳號是root  
![](/assets/images/2021-01-20-try_gitlab/login.PNG)  
登入後長這樣，就能開使用囉  
![](/assets/images/2021-01-20-try_gitlab/home.PNG)  

## 建立使用者

安全起見，不要用root來操作比較安全，順便玩玩管理git server?  

![](/assets/images/2021-01-20-try_gitlab/create_user_home.PNG)  
按下`New User`後就照自己的資料填吧  
![](/assets/images/2021-01-20-try_gitlab/user_data.PNG)  
創好囉～  
![](/assets/images/2021-01-20-try_gitlab/create_user_success.PNG)  

登出後，登入新的使用者（密碼他會寄信到使用者的信箱中），他會要你設定新的密碼  
![](/assets/images/2021-01-20-try_gitlab/new_password_for_new_user.PNG)  
設定完登入後，界面少了admin的管理功能  
![](/assets/images/2021-01-20-try_gitlab/home_for_new_user.PNG)  


## 管理專案

### 建立專案

按下Create a Project  
![](/assets/images/2021-01-20-try_gitlab/create_new_project_categories.PNG)  
選擇Create blank project後接著就這定自己的專案名稱囉  
![](/assets/images/2021-01-20-try_gitlab/new_project_setting.PNG)  
建立好後  
![](/assets/images/2021-01-20-try_gitlab/new_project_home.PNG)  

### 設定SSH key

可以看到這邊有提示要新增ssh key，因為現在很多git server好像都要廢除用密碼登入的方式做git操作，就來設定吧~  

![](/assets/images/2021-01-20-try_gitlab/need_ssh_key.PNG)  

產生key  
```shell
$ ssh-keygen -t rsa -C "your email@gmail.com"
Generating public/private rsa key pair.
Enter file in which to save the key (/home/zonda/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/zonda/.ssh/id_rsa.
Your public key has been saved in /home/zonda/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:/YZ/XXXXXXXXXXXXXXXXXXXXXXXXXXXXX your email@gmail.com
The key's randomart image is:
+---[RSA 2048]----+
|               . |
|              E .|
|           . = o.|
|         xxxxxxxx|
|        xxxxxxxxx|
|           xxxxxx|
|          .=o+=+*|
|          .o+**@=|
|            o*@=*|
+----[SHA256]-----+
```

接著將.ssh/id_rsa.pub檔案內容貼到
要clone 新專案的話可以從這  
![](/assets/images/2021-01-20-try_gitlab/paste_ssh_key_to_gitlab.PNG)  
![](/assets/images/2021-01-20-try_gitlab/create_ssh_key.PNG)  

### Git

#### Clone

要clone 新專案的話可以從這  
![](/assets/images/2021-01-20-try_gitlab/git_clone_path.PNG)  
PS: 記得將gitlab.example.com加到自己電腦的host設定並指到localhost，或是把gitlab.example.com轉成localhost  

```shell
$ git clone git@gitlab.example.com:Zonda/test_project.git
Cloning into 'test_project'...
The authenticity of host 'gitlab.example.com (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:5NmCKtnHfWnetN/DEN0gyJsnJ4xvjfvxUYTR4Hi8z/8.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'gitlab.example.com' (ECDSA) to the list of known hosts.
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (3/3), done.
$ cd test_project
$ ls
README.md
```

#### Push

隨便改點東西push上去  

```shell
$ git push
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Writing objects: 100% (3/3), 286 bytes | 143.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0)
To gitlab.example.com:Zonda/test_project.git
   34c9e9d..7de3ba6  master -> master
```

![](/assets/images/2021-01-20-try_gitlab/push_new_commit.PNG)  

暫時先到這囉~~  
有玩到新功能再更新  
