---
layout: post
title:  "Git - Split repository"
date:   2019-10-19 15:33:00 +0800
categories: Git
---

## 前言

以前曾經碰過一個git repository中有多個project的事情，而之後突然要拆分成各個repository，因此來記錄一下怎麼解決這問題。
![split_repository](/assets/images/2019-10-19-git_split_repository/split_repository.PNG)  

## 過程

假設我們現在有一個repository有2個project分別為`tool_1`和`tool_2`

![original_repository](/assets/images/2019-10-19-git_split_repository/original_repository.PNG)  

```text
git_test_project
├── tool_1
│   ├── config.txt
│   └── main.py
└── tool_2
    ├── config.txt
    └── main.go
```

### 分離tool_1

`git filter-branch --prune-empty --subdirectory-filter {foler name}  {branch name}`

```text
λ git branch tool_1

λ git filter-branch --prune-empty --subdirectory-filter tool_1 tool_1
Rewrite 34133531ba9fabc8f82161f5c8708fecf8d04dc1 (2/3) (1 seconds passed, remaining 0 predicted)
Ref 'refs/heads/tool_1' was rewritten
```

![new_tool_1_branch_lg](/assets/images/2019-10-19-git_split_repository/new_tool_1_branch_lg.PNG)  
![new_tool_1_branch_lg_gui](/assets/images/2019-10-19-git_split_repository/new_tool_1_branch_lg_gui.PNG)  

接下來新增一個資料夾叫`tool_1`，並且在那個資料夾下`git init`，而新增的資料夾路徑是`D:\self\project\tool_1`，這路徑等等會用到  

接下來回到`git_test_project`下，新增新的remote，remote的路徑為剛剛新建的資料夾路徑  

```text
λ git remote set-url tool_1 D:/self/project/tool_1

λ git remote -v
tool_1  D:/self/project/tool_1 (fetch)
tool_1  D:/self/project/tool_1 (push)
```

接者將我們tool_1 push到新建的資料夾中

`git push {remote} {local branch}:{remote branch}`  

```text
λ git push tool_1 tool_1
Enumerating objects: 9, done.
Counting objects: 100% (9/9), done.
Delta compression using up to 12 threads
Compressing objects: 100% (4/4), done.
Writing objects: 100% (9/9), 725 bytes | 725.00 KiB/s, done.
Total 9 (delta 0), reused 0 (delta 0)
To D:/self/project/tool_1
 * [new branch]      tool_1 -> tool_1
```

而另一邊會看到  

![first_tool_1](/assets/images/2019-10-19-git_split_repository/first_tool_1.PNG)  

接著將tool_1 merge 進master  
![after_merge](/assets/images/2019-10-19-git_split_repository/after_merge.PNG)  

如果tool_1這個branch不要了的話，就`git branch -d tool_1`  

接著就可以用一樣的步驟分離tool_2囉!  

### subtree

上面在分離log時是用`filter-branch`，還有另一個功能叫做`subtree`能做到一樣的事情  

`git subtree split -P {folder path} -b {branch name}`  

```text
λ git subtree split -P tool_2 -b "tool_2"
Created branch 'tool_2'
4876dda5ff1a8f60574d3d9161784997f8345dcb
```

![subtree](/assets/images/2019-10-19-git_split_repository/subtree.PNG)  
