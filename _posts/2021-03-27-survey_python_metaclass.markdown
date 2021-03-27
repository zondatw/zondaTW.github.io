---
layout: post
title:  "Survey python metaclass"
date:   2021-03-27 17:57:00 +0800
categories: Python
---

## 前言

最近在研究優化公司的系統，剛好研究在singleton實做時，碰到很久沒碰到的metaclass，因此就來紀錄一下，不然每次都要重新複習一次。

## Python 的 type

很多人在寫python時，很常以為type是用來判斷一個object的類別，但是當你顯示出type的doc時，會發現type其實是返回你傳入的object的object's type([Type object](https://docs.python.org/3.7/library/stdtypes.html#type-objects))，以及type可以用來創建新的type。  

```python
In [1]: type?
Init signature: type(self, /, *args, **kwargs)
Docstring:
type(object_or_name, bases, dict)
type(object) -> the object's type
type(name, bases, dict) -> a new type
Type:           type
Subclasses:     ABCMeta, EnumMeta, _TemplateMetaclass, MetaHasDescriptors, PyCStructType, UnionType, PyCPointerType, PyCArrayType, PyCSimpleType, PyCFuncPtrType, ...
```

列出Type object example:

```python
In [6]: type(1)
Out[6]: int

In [7]: type(1.0)
Out[7]: float

In [8]: type("test")
Out[8]: str

In [9]: type({})
Out[9]: dict

In [10]: type([])
Out[10]: list

In [11]: type(type)
Out[11]: type
```

有沒有在上面的範例中看到一個很神奇的地方，沒錯！就是第11項，type(type)返回type，在這邊回想一下，在剛接觸python的時候，是不是有很多文章都說python內的所有東西都是object，再看一下上面提到的type可以用來創建新的type，是不是想到了啊，沒錯，python所有東西的源頭就是type，你平時所在用的class，其實就是type幫你實現出來的。  

class example ([官方doc](https://docs.python.org/3.7/library/functions.html#type)):

```python
class DemoParent:
    test_parent_val = 456

    def show_parent(self):
        print(self.test_parent_val)


class Demo(DemoParent):
    test_val = 123

    def show(self):
        print(self.test_val)

In [2]: demo = Demo()

In [3]: demo.test_parent_val
Out[3]: 456

In [4]: demo.test_val
Out[4]: 123

In [5]: demo.show()
123

In [6]: demo.show_parent()
456

In [7]: demo.__class__
Out[7]: __main__.Demo

In [8]: demo.__class__.__bases__
Out[8]: (__main__.DemoParent,)
```

type example:

```python
DemoParent = type(
    "DemoParent", # name
    (),           # bases
    {             # dict
        "test_parent_val": 456,
        "show_parent": lambda self: print(self.test_parent_val),
    }
)
Demo = type(
    "Demo",        # name
    (DemoParent,), # bases
    {              # dict
        "test_val": 123,
        "show": lambda self: print(self.test_val),
    }
)

In [2]: demo = Demo()

In [3]: demo.test_parent_val
Out[3]: 456

In [4]: demo.test_val
Out[4]: 123

In [5]: demo.show()
123

In [6]: demo.show_parent()
456

In [7]: demo.__class__
Out[7]: __main__.Demo

In [8]: demo.__class__.__bases__
Out[8]: (__main__.DemoParent,)
```

透過上面的範例應該可以輕鬆看出type是怎麼實做出我們的class了吧！  
同時應該也能發現另一件事情，class是透過type實做出來的，instance是透過class實做出來的，所以  

```text
          實做          實做
instance -----> class ------> type
```

## Metaclass

那什麼是metaclass呢，他一個能協助我們處理創建class的type，對你沒看錯，他是type，平常在設計自己的metaclass時，是需要繼承type的，所以  

```text
          實做          實做
instance -----> class ------> metaclass
```

metaclass example:

```python
class DemoMeta(type):
    def __new__(cls, *args, **kwargs):
        new_cls = super().__new__(cls, *args, **kwargs)
        new_cls.test_meta_val = 789
        return new_cls

class Demo(metaclass=DemoMeta):
    def show(self):
        print(self.test_meta_val)

In [2]: demo = Demo()

In [3]: demo.show()
789

In [4]: Demo.test_meta_val
Out[4]: 789
```

在這個範例中，我們在new出一個class後，補上一個test_meta_val的attribute，所以當其他class使用這個metaclass時，就會有這個attribute囉～  
注意一下範例第4項，為什麼這邊會有test_meta_val呢？因為剛剛所提到的type是用來創建class，而創見時是透過__new__，因此我們在__new__中改變的是class，這個class等同於  

```python
class Demo:
    test_meta_val = 789

    def show(self):
        print(self.test_meta_val)
```

## 範例: Singleton

接著來弄個實做個範例吧  
在實做前，首先我們先來了解一個instance、一個class、一個metaclass創建的順序與過程。  

Demo file:

```python

class DemoMetaclass(type):
    def __init__(cls, *args, **kwargs):
        print("DemoMetaclass: init")
        return super().__init__(*args, **kwargs)

    def __new__(cls, *args, **kwargs):
        print("DemoMetaclass: new")
        return super().__new__(cls, *args, **kwargs)

    def __call__(cls, *args, **kwargs):
        print("DemoMetaclass: call")
        return super().__call__(*args, **kwargs)


class Demo(metaclass=DemoMetaclass):
    def __init__(cls, *args, **kwargs):
        print("Demo: init")
        return super().__init__(*args, **kwargs)

    def __new__(cls, *args, **kwargs):
        print("Demo: new")
        return super().__new__(cls, *args, **kwargs)
```

在ipython中執行:  

```python
In [1]: %run demo.py
DemoMetaclass: new
DemoMetaclass: init

In [2]: demo = Demo()
DemoMetaclass: call
Demo: new
Demo: init
```

在這個例子中應該可以輕鬆看出，當程式剛開始執行時，會去創建class: Demo，而Demo的metaclass是DemoMetaclass，所以可以看到執行了DemoMetaclass的`__new__` -> `__init__`。  
當要透過Demo創建demo這個instance時，會先去執行DemoMetaclass的`__call__`接著在執行Demo的`__new__` -> `__init__`。

因此當我們要實做Singleton的metaclass時，要把他放在__call__中  

Singleton metaclass:  

```python
class SingletonMetaclass(type):
    _instance = None
    def __call__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__call__(*args, **kwargs)
        return cls._instance

class Demo(metaclass=SingletonMetaclass):
    def __init__(self):
        self.test_val = 456

    def show(self):
        print(self.test_val)

demo1 = Demo()
demo2 = Demo()
print(id(demo1)) # 2025345058800
print(id(demo2)) # 2025345058800
print(demo1 == demo2) # True
demo1.show() # 456
demo2.show() # 456
demo1.test_val = 789
demo1.show() # 789
demo2.show() # 789
```

順便補一個不是metaclass的Singleton寫法:

```python
class Singleton(object):
    _instance = None
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

class Demo(Singleton):
    def __init__(self):
        self.test_val = 456

    def show(self):
        print(self.test_val)

demo1 = Demo()
demo2 = Demo()
print(id(demo1)) # 1987025700848
print(id(demo2)) # 1987025700848
print(demo1 == demo2) # True
demo1.show() # 456
demo2.show() # 456
demo1.test_val = 789
demo1.show() # 789
demo2.show() # 789
```