---
layout: post
title:  "Angular - part 1"
date:   2019-08-11 15:27:00 +0800
categories: Angular
---

## 前言

想玩玩angular就來玩玩囉~

## angular cli

### install

`npm install -g @angular/cli`  

```text
$ ng new angular-demo
? Would you like to add Angular routing? Yes
? Which stylesheet format would you like to use? CSS
...
```

### start server

```text
$ cd angular-demo
$ ng serve --open
 10% building 3/3 modules 0 activei ｢wds｣: Project is running at http://localhost:4200/webpack-dev-server/
i ｢wds｣: webpack output is served from /
i ｢wds｣: 404s will fallback to //index.html

chunk {main} main.js, main.js.map (main) 11.5 kB [initial] [rendered]
chunk {polyfills} polyfills.js, polyfills.js.map (polyfills) 251 kB [initial] [rendered]
chunk {runtime} runtime.js, runtime.js.map (runtime) 6.09 kB [entry] [rendered]
chunk {styles} styles.js, styles.js.map (styles) 16.3 kB [initial] [rendered]
chunk {vendor} vendor.js, vendor.js.map (vendor) 4.02 MB [initial] [rendered]
Date: 2019-08-11T08:00:47.498Z - Hash: 49e90aad52868bc71162 - Time: 8621ms
** Angular Live Development Server is listening on localhost:4200, open your browser on http://localhost:4200/ **
i ｢wdm｣: Compiled successfully.
```

打開[http://localhost:4200/](http://localhost:4200/)  
會出現  
![angular_start](/assets/images/2019-08-11-angular_part_1/angular_start.PNG)  

## Reference

[官方doc](https://angular.tw/guide/setup-local?fbclid=IwAR1CyNRVwehsdLuQYwcLAlCcCmKyI9v5L612TzeUfXFBCDlx_BXHurdjlyA)  