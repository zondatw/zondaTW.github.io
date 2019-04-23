---
layout: post
title:  "Golang dlv debug"
date:   2019-04-23 19:38:24 +0800
categories: Golang
---
因為最近在玩Golang，而寫程式一定會需要debug，所以來記錄一下關於Golang dlv debug怎麼用的小筆記。  

首先一定要安裝，安裝指令`go get -u github.com/derekparker/delve/cmd/dlv`  
安裝完了以後呢，來寫個小小的demo程式  

```go
// main.go
package main

import (
  "fmt"
)

func printName(name string) {
  fmt.Printf("I'm %s.\n", name)
}

func main() {
  name := "HaHa"
  fmt.Printf("Hello %s!\n", name)
  printName(name)
}
```

安裝完了dlv，也寫好了小小的demo程式，接下來就要開始正式Debug喽~  
啟動debug指令:  

```text
$ dlv debug main.go
Type 'help' for list of commands.
(dlv)
```

看起來是不是感覺跟gdb蠻像的，是的沒錯，連接下來的指令都差不多。  
首先來下個斷點，而斷點有2種下法:  

* 針對function : `package.function`  
* 針對程式的第幾行 : `file name:line number`  

```text
# 針對function
(dlv) b main.main
Breakpoint 1 set at 0x4a26a8 for main.main() ./main.go:12

# 針對程式的第幾行
(dlv) b main.go:12
Breakpoint 1 set at 0x4a26a8 for main.main() ./main.go:12
```

下完斷點後，我們要讓程式執行到我們的斷點，這時跟gdb一樣下`c`:

```text
(dlv) c
> main.main() ./main.go:12 (hits goroutine(1):1 total:1) (PC: 0x4a26a8)
     7: func printName(name string) {
     8:         fmt.Printf("I'm %s\n", name)
     9: }
    10:
    11:
=>  12: func main() {
    13:         name := "HaHa"
    14:         fmt.Printf("Hello %s!\n", name)
    15:         printName(name)
    16: }
```

而接下來逐步debug的指令也與gdb雷同，分別為:  

* 跳過函數的下一步: `n`
* 進入函數的下一步: `s`
* 跳出函數: `stepout`

就稍微的簡短介紹一下，而更多詳細的cmd可以參考這裡[dlv cmd][dlv-cmd]

[dlv-cmd]: https://github.com/go-delve/delve/tree/master/Documentation/cli#stepout
