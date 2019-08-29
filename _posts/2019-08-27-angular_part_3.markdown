---
layout: post
title:  "Angular - part 3"
date:   2019-08-27 21:05:00 +0800
categories: Angular
---

## 前言

繼續來寫Todo list的小專案吧

## 創建 Service

![create_todo_service](/assets/images/2019-08-27-angular_part_3/create_todo_service.PNG)  

```typescript
// todo.service.ts
import { Injectable } from '@angular/core';
import { Todo } from './todo';
import { TODOS } from './mock-todos';


@Injectable({
  providedIn: 'root'
})
export class TodoService {

  constructor() { }

  getTodos(): Todo[] {
    return TODOS;
  }
}
```

```typescript
// todos.component.ts
import { Component, OnInit } from '@angular/core';
import { Todo } from '../todo';
import { TodoService } from '../todo.service';

@Component({
  selector: 'app-todos',
  templateUrl: './todos.component.html',
  styleUrls: ['./todos.component.css']
})
export class TodosComponent implements OnInit {
  todos: Todo[];
  selectedTodo: Todo;

  constructor(
    private todoService: TodoService
  ) { }

  ngOnInit() {
    this.getTodos();
  }

  getTodos(): void {
    this.todos = this.todoService.getTodos();
  }

  onSelect(todo: Todo): void {
    this.selectedTodo = todo;
  }
}
```

## 增加 todos routing

將path設定在app-routing.modles.ts中, 如果在init時沒有出現這檔案，請執行`ng generate module app-routing --flat --module=app`  

```typescript
// app-routing.module.ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { TodosComponent } from './todos/todos.component';

const routes: Routes = [
  { path: '', redirectTo: '/todos', pathMatch: 'full' },
  { path: "todos", component: TodosComponent },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

```html
<!-- app.component.html -->
<h1>{{title}}</h1>
<router-outlet></router-outlet>
```

試著連接看看[http://localhost:4200/](http://localhost:4200/) 和 [http://localhost:4200/todos](http://localhost:4200/todos)  

## 增加 todo detail routing

```typescript
// todo.ts
export class Todo {
  "id": number;
  "title": string;
  "description": string;
}
```

```typescript
// mock-todos.ts
import {Todo} from './todo';

export const TODOS: Todo[] = [
  {
    id: 1,
    title: 'Coding',
    description: 'Write some code.',
  },
  {
    id: 2,
    title: 'Eating',
    description: 'Eat some food.',
  },
  {
    id: 3,
    title: 'Sleeping',
    description: 'Want some sleep.',
  },
]
```

```typescript
// app-routing.module.ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { TodosComponent } from './todos/todos.component';
import { TodoDetailComponent } from './todo-detail/todo-detail.component'

const routes: Routes = [
  { path: '', redirectTo: '/todos', pathMatch: 'full' },
  { path: "todos", component: TodosComponent },
  { path: "detail/:id", component: TodoDetailComponent },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

```html
<!-- todos.component.html -->
<h2>Todo List</h2>
<ul class="todos">
  <li *ngFor="let todo of todos"
      (click)="onSelect(todo)"
      routerLink="/detail/{{todo.id}}"
  >
    <h4>{{todo.title}}</h4>
    <p>{{todo.description}}</p>
  </li>
</ul>
```

```typescript
// todo.service.ts
import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';
import { Todo } from './todo';
import { TODOS } from './mock-todos';


@Injectable({
  providedIn: 'root'
})
export class TodoService {

  constructor() { }

  getTodos(): Observable<Todo[]> {
    return of(TODOS);
  }

  getTodo(id: number): Observable<Todo> {
    return of(TODOS.find(todo => todo.id == id));
  }
}
```

```typescript
// todo-detail.component.ts
import { Component, OnInit, Input } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Location } from '@angular/common';
import {Todo} from '../todo';
import { TodoService }  from '../todo.service';

@Component({
  selector: 'app-todo-detail',
  templateUrl: './todo-detail.component.html',
  styleUrls: ['./todo-detail.component.css']
})
export class TodoDetailComponent implements OnInit {
  @Input() todo: Todo;

  constructor(
    private route: ActivatedRoute,
    private todoService: TodoService,
    private location: Location
  ) { }

  ngOnInit() {
    this.getTodo();
  }

  getTodo(): void {
    const id = +this.route.snapshot.paramMap.get('id');
    this.todoService.getTodo(id)
      .subscribe(todo => this.todo = todo);
  }
}
```

![todo_detail_page](/assets/images/2019-08-27-angular_part_3/todo_detail_page.PNG)  

## 新增 back button

```html
<!-- todo-detail.component.html -->
<div *ngIf="todo">
  <h2>{{todo.title}} Detail</h2>
  <div>
    <label>Description:</label>
    <p>{{todo.description}}</p>
  </div>
</div>
<button (click)="goBack()">go back</button>
```

```typescript
// todo-detail.component.ts
import { Component, OnInit, Input } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Location } from '@angular/common';
import {Todo} from '../todo';
import { TodoService }  from '../todo.service';

@Component({
  selector: 'app-todo-detail',
  templateUrl: './todo-detail.component.html',
  styleUrls: ['./todo-detail.component.css']
})
export class TodoDetailComponent implements OnInit {
  @Input() todo: Todo;

  constructor(
    private route: ActivatedRoute,
    private todoService: TodoService,
    private location: Location
  ) { }

  ngOnInit() {
    this.getTodo();
  }

  getTodo(): void {
    const id = +this.route.snapshot.paramMap.get('id');
    this.todoService.getTodo(id)
      .subscribe(todo => this.todo = todo);
  }

  goBack(): void {
    this.location.back();
  }
}
```

part3就先到這囉!
