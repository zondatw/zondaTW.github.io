---
layout: post
title:  "Angular - part 2"
date:   2019-08-22 20:27:00 +0800
categories: Angular
---

## 前言

來寫個Todo list的小專案當練習吧

## 創建新專案

![create_project](/assets/images/2019-08-22-angular_part_2/create_project.PNG)  
![open_server](/assets/images/2019-08-22-angular_part_2/open_serve.PNG)  
![init_start](/assets/images/2019-08-22-angular_part_2/init_start.PNG)  

## 創建 todos component

![create_todo_component](/assets/images/2019-08-22-angular_part_2/create_todo_component.PNG)  

```typescript
// todos.component.ts
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-todos',
  templateUrl: './todos.component.html',
  styleUrls: ['./todos.component.css']
})
export class TodosComponent implements OnInit {
  todo = "Coding"

  constructor() { }

  ngOnInit() {
  }

}
```

```html
<!-- todos.component.html -->
<p>{{todo}}</p>
```

```html
<!-- app.component.html -->
<h1>{{title}}</h1>
<app-todos></app-todos>
```

Will see:  
![only_one_todo](/assets/images/2019-08-22-angular_part_2/only_one_todo.PNG)  

## 創建 todos class

建立src/app/todo.ts這個檔案  

```typescript
// todo.ts
export class Todo {
  "title": string;
  "description": string;
}
```

``` typescript
// todos.component.ts
import { Component, OnInit } from '@angular/core';
import {Todo} from '../todo';

@Component({
  selector: 'app-todos',
  templateUrl: './todos.component.html',
  styleUrls: ['./todos.component.css']
})
export class TodosComponent implements OnInit {
  todo: Todo = {
    title: "Coding",
    description: "Write some code.",
  }

  constructor() { }

  ngOnInit() {
  }

}
```

```html
<h2>{{todo.title}}</h2>
<div><span>{{todo.description}}</span></div>
```

你會看到畫面變成  
![todo_class_page](/assets/images/2019-08-22-angular_part_2/todo_class_page.PNG)  

## 創建 todos mock

建立src/app/mock-todos.ts這個檔案  

```typescript
// mock-todos.ts
import {Todo} from './todo';

export const TODOS: Todo[] = [
  {
    title: 'Coding',
    description: 'Write some code.',
  },
  {
    title: 'Eating',
    description: 'Eat some food.',
  },
  {
    title: 'Sleeping',
    description: 'Want some sleep.',
  },
]
```

## 顯示 Todo list

```typescript
// todos.component.ts
import { Component, OnInit } from '@angular/core';
import {TODOS} from '../mock-todos';

@Component({
  selector: 'app-todos',
  templateUrl: './todos.component.html',
  styleUrls: ['./todos.component.css']
})
export class TodosComponent implements OnInit {
  todos = TODOS;

  constructor() { }

  ngOnInit() {
  }

}
```

```html
<!-- todos.component.html -->
<h2>Todo List</h2>
<ul class="todos">
  <li *ngFor="let todo of todos">
    <h4>{{todo.title}}</h4>
    <p>{{todo.description}}</p>
  </li>
</ul>
```

畫面會變化成:  
![todo_list_page](/assets/images/2019-08-22-angular_part_2/todo_list_page.PNG)  

## 建立 onSelect 功能

```typescript
// todos.component.ts
import { Component, OnInit } from '@angular/core';
import {TODOS} from '../mock-todos';
import { Todo } from '../todo';

@Component({
  selector: 'app-todos',
  templateUrl: './todos.component.html',
  styleUrls: ['./todos.component.css']
})
export class TodosComponent implements OnInit {
  todos = TODOS;
  selectedTodo: Todo;

  constructor() { }

  ngOnInit() {
  }

  onSelect(todo: Todo): void {
    this.selectedTodo = todo;
  }
}
```

```html
<!-- todos.component.html -->
<h2>Todo List</h2>
<ul class="todos">
  <li *ngFor="let todo of todos" (click)="onSelect(todo)">
    <h4>{{todo.title}}</h4>
    <p>{{todo.description}}</p>
  </li>
</ul>

<div *ngIf="selectedTodo">
  <h2>{{selectedTodo.title}} Detail</h2>
  <div>
    <label>Description:</label>
    <p>{{selectedTodo.description}}</p>
  </div>
</div>
```

任意點選一個todo後，下方會顯示todo的detail:  
![todo_list_select_page](/assets/images/2019-08-22-angular_part_2/todo_list_select_page.PNG)

## 創建 todo detail component

執行`ng generate component todo-detail`  

```typescript
// todo-detail.component.ts
import { Component, OnInit, Input } from '@angular/core';
import {Todo} from '../todo';

@Component({
  selector: 'app-todo-detail',
  templateUrl: './todo-detail.component.html',
  styleUrls: ['./todo-detail.component.css']
})
export class TodoDetailComponent implements OnInit {
  @Input() todo: Todo;

  constructor() { }

  ngOnInit() {
  }
}
```

```html
<!-- todo-detail.component.html -->
<div *ngIf="todo">
  <h2>{{todo.title}} Detail</h2>
  <div>
    <label>Description:</label>
    <p>{{todo.description}}</p>
  </div>
</div>
```

```typescript
// todos.component.ts
import { Component, OnInit } from '@angular/core';
import {TODOS} from '../mock-todos';
import { Todo } from '../todo';

@Component({
  selector: 'app-todos',
  templateUrl: './todos.component.html',
  styleUrls: ['./todos.component.css']
})
export class TodosComponent implements OnInit {
  todos = TODOS;
  selectedTodo: Todo;

  constructor() { }

  ngOnInit() {
  }

  onSelect(todo: Todo): void {
    this.selectedTodo = todo;
  }
}
```

```html
<h2>Todo List</h2>
<ul class="todos">
  <li *ngFor="let todo of todos" (click)="onSelect(todo)">
    <h4>{{todo.title}}</h4>
    <p>{{todo.description}}</p>
  </li>
</ul>

<app-todo-detail [todo]="selectedTodo"></app-todo-detail>
```

```typescript
// app.module.ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { TodosComponent } from './todos/todos.component';
import { TodoDetailComponent } from './todo-detail/todo-detail.component';

@NgModule({
  declarations: [
    AppComponent,
    TodosComponent,
    TodoDetailComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

part2就先到這囉!  
