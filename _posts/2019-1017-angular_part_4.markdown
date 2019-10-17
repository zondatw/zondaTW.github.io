---
layout: post
title:  "Angular - part 4"
date:   2019-10-18 00:33:00 +0800
categories: Angular
---

## 前言

繼續來寫Todo list的小專案吧  
重點顯示功能都完成了，目前是用寫死的Data來做顯示，但實際上一定是會用動態的資料，因此來試著把東西改成動態的囉!
參考[官方doc](https://angular.tw/tutorial/toh-pt6)  

## HTTP

啟用HTTP  

```typescript
// app.module.ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { HttpClientModule }    from '@angular/common/http';

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
    AppRoutingModule,
    HttpClientModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

## In memory wb api

### Create db

Install: `npm install angular-in-memory-web-api --save`  

創建 InMemoryData 的 Service  
`ng generate service InMemoryData`  

```typescript
// in-memory-data.service.ts
import { InMemoryDbService } from 'angular-in-memory-web-api';
import { Todo } from './todo';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class InMemoryDataService implements InMemoryDbService {
  createDb() {
    const todos = [
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
      {
        id: 4,
        title: 'test',
        description: 'Just test.',
      },
    ];

    return {todos};
  }

  genId(todos: Todo[]): number {
    return todos.length > 0 ? Math.max(...todos.map(todo => todo.id)) + 1 : 1;
  }

  constructor() { }
}
```

因為現在有memory api了，所以可以將`mock-todos.ts`刪掉囉!  


```typescript
// app.module.ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { HttpClientModule }    from '@angular/common/http';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { TodosComponent } from './todos/todos.component';
import { TodoDetailComponent } from './todo-detail/todo-detail.component';
import { HttpClientInMemoryWebApiModule } from 'angular-in-memory-web-api';
import { InMemoryDataService }  from './in-memory-data.service';

@NgModule({
  declarations: [
    AppComponent,
    TodosComponent,
    TodoDetailComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    HttpClientInMemoryWebApiModule.forRoot(
      InMemoryDataService, { dataEncapsulation: false }
    )
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

修改一下todo.service.ts

```typescript
// todo.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

import { Observable, of } from 'rxjs';
import { catchError, map, tap } from 'rxjs/operators';
import { Todo } from './todo';


@Injectable({
  providedIn: 'root'
})
export class TodoService {
  private todosUrl = 'api/todos';

  constructor(
    private http: HttpClient
  ) { }

  getTodos(): Observable<Todo[]> {
    return this.http.get<Todo[]>(this.todosUrl).pipe(
      catchError(this.handleError<Todo[]>('getTodos', []))
    );
  }

  getTodo(id: number): Observable<Todo> {
    const url = `${this.todosUrl}/${id}`;
    return this.http.get<Todo>(url).pipe(
      catchError(this.handleError<Todo>(`getTodo id=${id}`))
    );
  }

  private handleError<T> (operation='operation', result?: T) {
    return (error: any): Observable<T> => {
      console.error(error);
      return of(result as T);
    };
  }
}
```

這樣他就會去拿DB中的資料囉!  
![in_memory](/assets/images/2019-10-17-angular_part_4/in_memory_db.PNG)  


## Modify todo info

```typescript
// app.module.ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { HttpClientModule }    from '@angular/common/http';
import { FormsModule } from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { TodosComponent } from './todos/todos.component';
import { TodoDetailComponent } from './todo-detail/todo-detail.component';
import { HttpClientInMemoryWebApiModule } from 'angular-in-memory-web-api';
import { InMemoryDataService }  from './in-memory-data.service';

@NgModule({
  declarations: [
    AppComponent,
    TodosComponent,
    TodoDetailComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    HttpClientInMemoryWebApiModule.forRoot(
      InMemoryDataService, { dataEncapsulation: false }
    ),
    FormsModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

```typescript
// todo.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

import { Observable, of } from 'rxjs';
import { catchError, map, tap } from 'rxjs/operators';
import { Todo } from './todo';


@Injectable({
  providedIn: 'root'
})
export class TodoService {
  private todosUrl = 'api/todos';

  constructor(
    private http: HttpClient
  ) { }

  getTodos(): Observable<Todo[]> {
    return this.http.get<Todo[]>(this.todosUrl).pipe(
      catchError(this.handleError<Todo[]>('getTodos', []))
    );
  }

  getTodo(id: number): Observable<Todo> {
    const url = `${this.todosUrl}/${id}`;
    return this.http.get<Todo>(url).pipe(
      catchError(this.handleError<Todo>(`getTodo id=${id}`))
    );
  }

  updateTodo (todo: Todo): Observable<any> {
    const httpOptions = {
      headers: new HttpHeaders({ 'Content-Type': 'application/json' })
    };

    return this.http.put(this.todosUrl, todo, httpOptions).pipe(
      catchError(this.handleError<any>('updateTodo'))
    );
  }

  private handleError<T> (operation='operation', result?: T) {
    return (error: any): Observable<T> => {
      console.error(error);
      return of(result as T);
    };
  }
}
```

```html
<!-- todo-detail.components.ts -->
<div *ngIf="todo">
  <h2>{{todo.title}} Detail</h2>
  <div>
    <p>
      <label>Title:
        <input [(ngModel)]="todo.title" placeholder="title"/>
      </label>
    </p>
    <p>
      <label>Description:
        <input [(ngModel)]="todo.description" placeholder="description"/>
      </label>
    </p>
  </div>
</div>
<button (click)="save()">save</button>
<button (click)="goBack()">go back</button>
```

```typescript
//todo-detail.components.ts
import { Component, OnInit, Input } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Location } from '@angular/common';

import { Todo } from '../todo';
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

  save(): void {
    this.todoService.updateTodo(this.todo)
      .subscribe(() => this.goBack());
  }
}
```

就可以修改DB中Todo的資料囉!  
![before_modify](/assets/images/2019-10-17-angular_part_4/before_modify.PNG)  
![ready_modify](/assets/images/2019-10-17-angular_part_4/ready_modify.PNG)  
![after_modify](/assets/images/2019-10-17-angular_part_4/after_modify.PNG)  

## Add new Todo

```typescript
// todo.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

import { Observable, of } from 'rxjs';
import { catchError, map, tap } from 'rxjs/operators';
import { Todo } from './todo';


const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json' })
};

@Injectable({
  providedIn: 'root'
})
export class TodoService {
  private todosUrl = 'api/todos';

  constructor(
    private http: HttpClient
  ) { }


  getTodos(): Observable<Todo[]> {
    return this.http.get<Todo[]>(this.todosUrl).pipe(
      catchError(this.handleError<Todo[]>('getTodos', []))
    );
  }

  getTodo(id: number): Observable<Todo> {
    const url = `${this.todosUrl}/${id}`;
    return this.http.get<Todo>(url).pipe(
      catchError(this.handleError<Todo>(`getTodo id=${id}`))
    );
  }

  updateTodo (todo: Todo): Observable<any> {
    return this.http.put(this.todosUrl, todo, httpOptions).pipe(
      catchError(this.handleError<any>('updateTodo'))
    );
  }

  addTodo (todo: Todo): Observable<any> {
    return this.http.post<Todo>(this.todosUrl, todo, httpOptions).pipe(
      catchError(this.handleError<any>('addTodo'))
    );
  }

  private handleError<T> (operation='operation', result?: T) {
    return (error: any): Observable<T> => {
      console.error(error);
      return of(result as T);
    };
  }
}
```

```html
<!-- todos.components.html -->
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

<div>
  <h4> Add new Todo </h4>
  <p>
    <label> Title:
      <input #todoTitle />
    </label>
  </p>
  <p>
    <label> Description:
      <input #todoDescription />
    </label>
  </p>

  <button (click)="add(todoTitle.value, todoDescription.value); todoTitle.value=''; todoDescription.value=''">
    add
  </button>
</div>
```

```typescript
// todos.components.ts
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
    this.todoService.getTodos()
      .subscribe(todos => this.todos = todos);
  }

  onSelect(todo: Todo): void {
    this.selectedTodo = todo;
  }

  add(title: string, description: string): void {
    title = title.trim();
    if (!title) {
      return ;
    }

    this.todoService.addTodo({title, description} as Todo)
      .subscribe(todo => {
        this.todos.push(todo);
      });
  }
}
```

就可以新增DB中Todo的資料囉!  
![before_add](/assets/images/2019-10-17-angular_part_4/before_add.PNG)  
![ready_add](/assets/images/2019-10-17-angular_part_4/ready_add.PNG)  
![after_add](/assets/images/2019-10-17-angular_part_4/after_add.PNG)  

## Delete Todo

```typescript
// todo.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

import { Observable, of } from 'rxjs';
import { catchError, map, tap } from 'rxjs/operators';
import { Todo } from './todo';


const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json' })
};

@Injectable({
  providedIn: 'root'
})
export class TodoService {
  private todosUrl = 'api/todos';

  constructor(
    private http: HttpClient
  ) { }


  getTodos(): Observable<Todo[]> {
    return this.http.get<Todo[]>(this.todosUrl).pipe(
      catchError(this.handleError<Todo[]>('getTodos', []))
    );
  }

  getTodo(id: number): Observable<Todo> {
    const url = `${this.todosUrl}/${id}`;
    return this.http.get<Todo>(url).pipe(
      catchError(this.handleError<Todo>(`getTodo id=${id}`))
    );
  }

  updateTodo (todo: Todo): Observable<any> {
    return this.http.put(this.todosUrl, todo, httpOptions).pipe(
      catchError(this.handleError<any>('updateTodo'))
    );
  }

  addTodo (todo: Todo): Observable<any> {
    return this.http.post<Todo>(this.todosUrl, todo, httpOptions).pipe(
      catchError(this.handleError<any>('addTodo'))
    );
  }

  deleteTodo (todo: Todo): Observable<any> {
    const url = `${this.todosUrl}/${todo.id}`;
    return this.http.delete<Todo>(url, httpOptions).pipe(
      catchError(this.handleError<any>('deleteTodo'))
    );
  }

  private handleError<T> (operation='operation', result?: T) {
    return (error: any): Observable<T> => {
      console.error(error);
      return of(result as T);
    };
  }
}
```

```html
<!-- todos.component.html -->
<h2>Todo List</h2>
<ul class="todos">
  <li *ngFor="let todo of todos"
      (click)="onSelect(todo)"
      routerLink="/detail/{{todo.id}}"
  >
    <h4>{{todo.title}}
      <button
        class="delete"
        title="delete todo"
        (click)="delete(todo)"
      >
        x
      </button>
    </h4>
    <p>{{todo.description}}</p>
  </li>
</ul>

<div>
  <h4> Add new Todo </h4>
  <p>
    <label> Title:
      <input #todoTitle />
    </label>
  </p>
  <p>
    <label> Description:
      <input #todoDescription />
    </label>
  </p>

  <button (click)="add(todoTitle.value, todoDescription.value); todoTitle.value=''; todoDescription.value=''">
    add
  </button>
</div>
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
    this.todoService.getTodos()
      .subscribe(todos => this.todos = todos);
  }

  onSelect(todo: Todo): void {
    this.selectedTodo = todo;
  }

  add(title: string, description: string): void {
    title = title.trim();
    if (!title) {
      return ;
    }

    this.todoService.addTodo({title, description} as Todo)
      .subscribe(todo => {
        this.todos.push(todo);
      });
  }

  delete(todo: Todo): void {
    this.todos = this.todos.filter(t => t !== todo);
    this.todoService.deleteTodo(todo).subscribe();
  }
}
```

![before_delete](/assets/images/2019-10-17-angular_part_4/before_delete.PNG)  
![after_delete](/assets/images/2019-10-17-angular_part_4/after_delete.PNG)  

part 4就先到這裡囉~  
