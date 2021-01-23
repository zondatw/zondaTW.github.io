---
layout: post
title:  "Try Jenkins"
date:   2021-01-22 01:57:00 +0800
categories: Jenkins
---

## 前言

想玩Jenkins很久了，最近剛好有衝動想玩，就來玩囉～  

## Setup

這邊採用docker來建制真方便～  

```shell
$ docker run --name jenkins -d --restart always -p 8080:8080 -p 50000:50000 -v /data/jenkins:/var/jenkins_home jenkins/jenkins:lts
$ docker ps
CONTAINER ID   IMAGE                  COMMAND                  CREATED          STATUS          PORTS                                              NAMES
8220bc6c4a1e   jenkins/jenkins:lts    "/sbin/tini -- /usr/…"   16 seconds ago   Up 12 seconds   0.0.0.0:8080->8080/tcp, 0.0.0.0:50000->50000/tcp   jenkins
```

接著連上[http://localhost:8080](http://localhost:8080)  
![](/assets/images/2021-01-22-try_jenkins/sign_in_jenkins.PNG)  

這邊要輸入密碼，他很貼心的跟你說密碼在哪了，就去找吧～  
```shell
$ docker exec -it jenkins cat /var/jenkins_home/secrets/initialAdminPassword
371ef4e7294145f99b4eebe097ec5052
```
輸入後，會進到安裝plugin的畫面  
![](/assets/images/2021-01-22-try_jenkins/setup_wizard_jenkins.PNG)  
第一次玩，就乖乖按Install suggested plugins吧  
![](/assets/images/2021-01-22-try_jenkins/setup_wizard_jenkins_installing.PNG)  
安裝玩後，接著要創建admin帳號  
![](/assets/images/2021-01-22-try_jenkins/create_first_admin_user.PNG)  
接著設定url，目前只是先玩玩看，就用default吧  
![](/assets/images/2021-01-22-try_jenkins/configure_url_jenkins.PNG)  
準備開使用囉～  
![](/assets/images/2021-01-22-try_jenkins/jenkins_ready.PNG)  
![](/assets/images/2021-01-22-try_jenkins/home.PNG)  

## Install plugin

因為等等會使用GitLab來當git server，所以先來安裝GitLab的plugin。  
![](/assets/images/2021-01-22-try_jenkins/click_manage_plugin.PNG)  

接著點選可用的，並在filter中輸入GitLab，再選擇需要的plugin，  
接下來因為我們目前都沒有任何任務在執行中，所以點選`直接安裝`，  
但如果是已經有在使用的Jenkins點選`下載並於重新啟動後安裝`比較安全。  
![](/assets/images/2021-01-22-try_jenkins/install_gitlab_plugin.PNG)  
勾選`當安裝完成且沒有工作正在執行時，重啟Jenkins`  
![](/assets/images/2021-01-22-try_jenkins/installing_gitlab_plugin.PNG)  
![](/assets/images/2021-01-22-try_jenkins/restart_after_install.PNG)  

## Setup GitLab

點選至設定系統  
![](/assets/images/2021-01-22-try_jenkins/click_setting_system.PNG)  

輸入GitLab的名稱和URL  
![](/assets/images/2021-01-22-try_jenkins/enter_gitlab_name_and_url_to_system_setting.PNG)  

接著按下Credentials旁的Add來新增Credential  
在新增前要先去GitLab拿access token  
![](/assets/images/2021-01-22-try_jenkins/create_gitlab_personal_access_token.PNG)  
![](/assets/images/2021-01-22-try_jenkins/get_gitlab_personal_access_token.PNG)  

接著把剛剛的access token輸入到API token且Kind選擇GitLab API Token  
![](/assets/images/2021-01-22-try_jenkins/set_jenkins_credential.PNG)  

新增完就來測試一下(因為我的GitLab也是架在docker中Jenkins會連不到，所以用ngrok幫忙架到外面)  
![](/assets/images/2021-01-22-try_jenkins/test_credential.PNG)  
測試完後就按儲存  


## 新增專案

點選新增作業  
![](/assets/images/2021-01-22-try_jenkins/create_project.PNG)  
再輸入名稱以及選擇`建置Free-Style軟體專案`  
![](/assets/images/2021-01-22-try_jenkins/create_free_style_sw_project.PNG)  

輸入描述和選擇GitLab Connection  
![](/assets/images/2021-01-22-try_jenkins/new_project_general.PNG)  
輸入指定的repository url和brunch  
![](/assets/images/2021-01-22-try_jenkins/new_project_repos_management.PNG)  
選擇`Build when a change is pushed to GitLab. GitLab webhook URL: http://localhost:8080/project/Demo`觸發  
![](/assets/images/2021-01-22-try_jenkins/new_project_setup_trigger.PNG)  
設定完後按儲存  

接著按下馬上建置  
![](/assets/images/2021-01-22-try_jenkins/press_immediately_setup.PNG)  

可以看到第一次建置失敗了  
![](/assets/images/2021-01-22-try_jenkins/first_setup_fail.PNG)  

就來Debug吧  
![](/assets/images/2021-01-22-try_jenkins/click_first_setup_fail_record.PNG)  
![](/assets/images/2021-01-22-try_jenkins/first_setup_fail_reason.PNG)  

Google了一下可能是跟clone的權限有關，  
才想起，我的GitLab有限制用ssh連線，  
就來把ssh key給補上吧  
![](/assets/images/2021-01-22-try_jenkins/create_cert_of_gitlab_ssh_key.PNG)  
![](/assets/images/2021-01-22-try_jenkins/select_cert_to_repos_manage.PNG)  

接著按下馬上建置，這次就看到成功囉  
![](/assets/images/2021-01-22-try_jenkins/second_setup_success.PNG)  
![](/assets/images/2021-01-22-try_jenkins/second_setup_success_detail.PNG)  

也可以幫他加入一些你想要的shell哦，  
![](/assets/images/2021-01-22-try_jenkins/add_setup_shell.PNG)  
![](/assets/images/2021-01-22-try_jenkins/add_setup_shell_output.PNG)  

接著來測試一下用gitlab push來觸發  
首先到gitlab中設定jenkins ci  
project name要跟上面建置的project一樣哦  
![](/assets/images/2021-01-22-try_jenkins/gitlab_jenkins_ci.PNG)  
![](/assets/images/2021-01-22-try_jenkins/gitlab_jenkins_ci_setting.PNG)  

接著push個commit，就可以看到jenkins被觸發囉  
![](/assets/images/2021-01-22-try_jenkins/trigger_by_git_push.PNG)  

就先到這拉～  
之後再研究其他功能  
