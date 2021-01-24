---
layout: post
title:  "Try Jenkins Pipeline"
date:   2021-01-23 17:57:00 +0800
categories: Jenkins
---

## 前言

之前小玩了一下Jenkins的Free-style專案，接著來玩玩Pipeline吧~  

## 建立Pipeline

點選新增作業  
![](/assets/images/2021-01-23-try_jenkins_pipeline/click_create_project.PNG)  
輸入item name並選Pipeline  
![](/assets/images/2021-01-23-try_jenkins_pipeline/create_pipeline.PNG)  

### 設定

#### General

![](/assets/images/2021-01-23-try_jenkins_pipeline/set_demo_pipeline_general.PNG)  

#### Build Triggers

![](/assets/images/2021-01-23-try_jenkins_pipeline/set_demo_pipeline_build_triggers.PNG)  

#### Build Triggers

![](/assets/images/2021-01-23-try_jenkins_pipeline/set_demo_pipeline_build_triggers.PNG)  

#### Pipeline

```pipeline
pipeline {
    agent any

    stages {
        stage('Stage 1') {
            steps {
                echo 'Hello stage 1'
            }
        }
        stage('Stage 2') {
            steps {
                echo 'Hello stage 2'
            }
        }
    }
}
```

![](/assets/images/2021-01-23-try_jenkins_pipeline/set_demo_pipeline_pipeline.PNG)  

建立成功  
![](/assets/images/2021-01-23-try_jenkins_pipeline/create_demo_pipeline_success.PNG)  

接著來測試看看，按下馬上建置，旁邊就會出現建置的過程和有無成功  
![](/assets/images/2021-01-23-try_jenkins_pipeline/press_immediately_setup.PNG)  

也可以按Log來看過程哦  
![](/assets/images/2021-01-23-try_jenkins_pipeline/see_stage1_log.PNG)  
![](/assets/images/2021-01-23-try_jenkins_pipeline/stage1_log.PNG)  

接著來玩玩用gitlab push來觸發  
但這邊有個小問題，因為設定時需要對應Pipeline專案名稱，  
但因為現在的名稱有空白，網頁url有空白會有問題，所以要先換一下名稱  
![](/assets/images/2021-01-23-try_jenkins_pipeline/rename_project_name.PNG)  

接著到GitLab中設定jenkins ci  
![](/assets/images/2021-01-23-try_jenkins_pipeline/gitlab_jenkins_ci.PNG)  
![](/assets/images/2021-01-23-try_jenkins_pipeline/gitlab_jenkins_ci_setting.PNG)  

接著push一個commit，可以看到Jenkins被觸發囉  
![](/assets/images/2021-01-23-try_jenkins_pipeline/push_trigger_by_gitlab.PNG)  


## 結合go test

因為要build go的執行檔，所以要先裝go plugin  
安裝plugin並重啟  
![](/assets/images/2021-01-23-try_jenkins_pipeline/install_go_plugin.PNG)  
接著點選Global Tool Configuration  
![](/assets/images/2021-01-23-try_jenkins_pipeline/click_global_tool_configuration.PNG)  
輸入名稱及指定的golang版本  
![](/assets/images/2021-01-23-try_jenkins_pipeline/set_golang_configure.PNG)  

接著先來拿credential id等等會用到，找到等等要pull的專案的credential  
![](/assets/images/2021-01-23-try_jenkins_pipeline/click_manage_credentials.PNG)  
![](/assets/images/2021-01-23-try_jenkins_pipeline/click_gitlab_example_credential.PNG)  
![](/assets/images/2021-01-23-try_jenkins_pipeline/click_update_gitlab_example_credential.PNG)  
![](/assets/images/2021-01-23-try_jenkins_pipeline/found_gitlab_credential_id.PNG)  



來修改專案的Pipeline  

```pipeline
pipeline {
    agent any
    tools {
        go 'go_1_13_15'
    }
    environment {
        GOPATH = ''
        CGO_ENABLED = 0
        GO111MODULE = 'on'
    }
    stages {
        stage('Checkout git project') {
            steps {
                git branch: 'master',
                    credentialsId: 'a0abXXXX-XXXX-XXXX-XXXX-XXXX668679eb',
                    url: 'http://gitlab.example.com/Zonda/todolist-server.git'
    
                sh "ls -lat"
            }
        }
       stage('Compile') {
            steps {
                sh 'go mod download'
                sh 'go build'
            }
        }
        stage('Test') {
            steps {
                sh 'go test -cover ./...'
            }
        }
    }
}
```
![](/assets/images/2021-01-23-try_jenkins_pipeline/update_pipeline.PNG)  

更新完後按下馬上建置，就成功囉  
![](/assets/images/2021-01-23-try_jenkins_pipeline/updated_pipeline_setup.PNG)  


## Reference

[Create a Continuous Deployment Pipeline with Golang and Jenkins](https://blog.couchbase.com/create-continuous-deployment-pipeline-golang-jenkins/)  
[Building Go projects using modules on Jenkins](https://bmuschko.com/blog/go-on-jenkins/)  