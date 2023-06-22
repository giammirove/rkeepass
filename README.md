Rkeepass
=========


`rkeepass` is command line keepass manager inspired by [pass](https://www.passwordstore.org)

#### Warning
This is my first rust project, be gentle!

#### Features
- add,delete entries and groups
- supports KeePass v4 databases
- no need to retype the password within a chosen timeout (default 120 sec)
- support for pinentry

#### How to build

```
cargo build --features save_kdbx4 --release
```

#### How to install

```
cargo install --path . 
```
