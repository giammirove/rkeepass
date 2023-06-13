use anyhow::{anyhow, Result};

use colored::Colorize;

use lazy_static::lazy_static;

use fork::{fork, Fork};
use keepass::db::Value;
use keepass::db::{Entry, Group, NodeRef, NodeRefMut};
use keepass::error::DatabaseKeyError;
use keepass::{db::Node, Database, DatabaseKey};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::{thread, time::Duration};

use clap::{Arg, ArgAction, ArgMatches, Command};
use configparser::ini::Ini;
use passwords::PasswordGenerator;
use text_io::read;

use home_dir::HomeDirExt;

pub static SOCKET_PATH: &'static str = "/tmp/rkeepass.sock";

pub static CONFIG_DIR_PATH: &'static str = "~/.config/rkeepass";
pub static CONFIG_PATH: &'static str = "~/.config/rkeepass/config.ini";

pub static DEF_TIMEOUT: &'static u64 = &120;

lazy_static! {
    pub static ref SOCKET: &'static Path = Path::new(SOCKET_PATH);
}

macro_rules! handle_wrap_search_rule {
    ($s:ident, $d:ident, $a:expr, $b:expr, $c:ident) => {
        if $a.starts_with($b) {
            handle_wrap_search(&mut $s, &$d, $a.replacen($b, "", 1).trim().to_string(), $c)?;
        }
    };
}

macro_rules! get_arg {
    ($l: ident, $f: literal) => {
        if let Some(tmp_opt) = $l.get_many::<String>($f) {
            tmp_opt.map(|s| s.as_str()).collect::<Vec<_>>().join("\n")
        } else {
            "".to_string()
        }
    };
}

trait MyGroup {
    fn my_get<'a>(&'a self, path: &[&str]) -> Option<NodeRef<'a>>;
}

impl MyGroup for Group {
    // the original version does not return the group
    // if it was the only input e.g. ["group"]
    fn my_get<'a>(&'a self, path: &[&str]) -> Option<NodeRef<'a>> {
        if path.is_empty() {
            Some(NodeRef::Group(self))
        } else {
            if path.len() == 1 {
                let head = path[0];
                self.children.iter().find_map(|n| match n {
                    Node::Group(g) => {
                        if g.name == head {
                            Some(n.as_ref())
                        } else {
                            None
                        }
                    }
                    Node::Entry(e) => {
                        e.get_title()
                            .and_then(|t| if t == head { Some(n.as_ref()) } else { None })
                    }
                })
            } else {
                let head = path[0];
                let tail = &path[1..path.len()];

                let head_group = self.children.iter().find_map(|n| match n {
                    Node::Group(g) if g.name == head => Some(g),
                    _ => None,
                })?;

                head_group.my_get(tail)
            }
        }
    }
}

fn handle_not_found(socket: &mut UnixStream) -> Result<()> {
    socket.write_fmt(format_args!(
        "{}",
        "[x] Entry not found !!!\n".to_string().red(),
    ))?;
    Ok(())
}

fn handle_list_entry(socket: &mut UnixStream, e: &Entry, space_n: i32, last: bool) -> Result<()> {
    let title = e.get_title().unwrap_or("(no title)");
    for _ in 0..space_n * 2 {
        socket.write_all(b" ")?;
    }
    let mut char: &str = "├──";
    if last == true {
        char = "└──"
    }
    socket.write_fmt(format_args!("{} {}\n", char, title))?;
    Ok(())
}

fn handle_list_group(socket: &mut UnixStream, g: &Group, space_n: i32) -> Result<()> {
    for _ in 0..space_n * 2 {
        socket.write_all(b" ")?;
    }
    socket.write_fmt(format_args!("{0}\n", g.name.purple()))?;
    let mut i = 0;
    for n in &g.children {
        match n {
            Node::Entry(e2) => {
                handle_list_entry(socket, e2, space_n + 1, i == g.children.len() - 1)?
            }
            Node::Group(g2) => handle_list_group(socket, g2, space_n + 1)?,
        }
        i += 1;
    }
    Ok(())
}

fn handle_list(socket: &mut UnixStream, db: &Database) -> Result<()> {
    handle_list_group(socket, &db.root, 0)?;
    Ok(())
}
fn handle_search(db: &Database, show_raw: String) -> Result<keepass::db::Entry> {
    let vecc: Vec<&str> = show_raw.split("/").collect();
    let arr = vecc.as_slice();
    if let Some(NodeRef::Entry(e)) = db.root.get(arr) {
        return Ok(e.clone());
    }

    Err(anyhow!("Not found"))
}
fn handle_wrap_search(
    socket: &mut UnixStream,
    db: &Database,
    raw: String,
    f: fn(socket: &mut UnixStream, e: Entry) -> Result<()>,
) -> Result<()> {
    if let Ok(e) = handle_search(db, raw) {
        f(socket, e)?;
        return Ok(());
    }
    handle_not_found(socket)
}

fn handle_show(socket: &mut UnixStream, e: Entry) -> Result<()> {
    let title = e.get_title().unwrap_or("(no title)");
    let url = e.get_url().unwrap_or("(no url)");
    let user = e.get_username().unwrap_or("(no username)");
    let pass = e.get_password().unwrap_or("(no password)");
    socket.write_fmt(format_args!(
        "{0}\n├── url: {1}\n├── username: {2}\n└── pass: {3}\n",
        title.blue(),
        url.cyan(),
        user.white(),
        pass.yellow().on_yellow()
    ))?;
    Ok(())
}

fn handle_copy(socket: &mut UnixStream, e: Entry) -> Result<()> {
    let pass = e.get_password().unwrap_or("");
    match cli_clipboard::set_contents(pass.to_owned()) {
        Err(_) => {
            socket.write_fmt(format_args!(
                "{}",
                "[x] Error copying to clipboard !!!\n".to_string().red(),
            ))?;
        }
        Ok(()) => {
            socket.write_fmt(format_args!(
                "{}",
                "[-] The password has been copied to the clipboard !!!\n"
                    .to_string()
                    .green(),
            ))?;
        }
    };
    Ok(())
}

fn handle_pass(socket: &mut UnixStream, e: Entry) -> Result<()> {
    let pass = e.get_password().unwrap_or("(no password)");
    socket.write_fmt(format_args!("{}\n", pass))?;
    Ok(())
}

fn handle_add(socket: &mut UnixStream, db: &mut Database, key: String, raw: String) -> Result<()> {
    let args: Vec<&str> = raw.split("\n").collect();

    let groups: Vec<&str> = args[0].split("/").collect();
    let arr = groups.as_slice();

    for i in 0..groups.len() - 1 {
        // if it already exists do nothing
        if let None = db.root.my_get(&arr[0..i + 1]) {
            // if not exists, get groups until here and add another one
            if let Some(NodeRefMut::Group(g2)) = db.root.get_mut(&arr[0..i]) {
                g2.children.push(Node::Group(Group::new(groups[i])));
            }
        }
        // }
    }

    if arr[arr.len() - 1] != "" {
        if let Some(NodeRefMut::Group(g)) = db.root.get_mut(&arr[0..arr.len() - 1]) {
            let mut entry = Entry::new();
            entry.fields.insert(
                "Title".to_string(),
                Value::Unprotected(arr[arr.len() - 1].to_string()),
            );
            if args[1] != "" {
                entry
                    .fields
                    .insert("URL".to_string(), Value::Unprotected(args[1].to_string()));
            }
            if args[2] != "" {
                entry.fields.insert(
                    "UserName".to_string(),
                    Value::Unprotected(args[2].to_string()),
                );
            }
            if args[3] != "" {
                entry.fields.insert(
                    "Password".to_string(),
                    Value::Unprotected(args[3].to_string()),
                );
            }

            g.children.push(Node::Entry(entry));

            #[cfg(feature = "save_kdbx4")]
            db.save(
                &mut File::create(read_config()?)?,
                DatabaseKey::with_password(key.as_str().clone()),
            )?;
        }
    }

    socket.write_fmt(format_args!(
        "{}",
        "[-] Entry added !!!\n".to_string().green(),
    ))?;
    Ok(())
}

fn handle_rem(socket: &mut UnixStream, db: &mut Database, key: String, raw: String) -> Result<()> {
    let ss = raw.split("/");
    let groups: Vec<&str> = ss.clone().filter(|x| *x != "").collect();
    let arr = groups.as_slice();
    let isgroup = ss.collect::<Vec<&str>>().len() != groups.len();

    if let Some(NodeRefMut::Group(g)) = db.root.get_mut(&arr[0..arr.len() - 1]) {
        let index = g
            .children
            .iter()
            .position(|x| {
                if isgroup {
                    if let Node::Group(e) = x {
                        return e.name == arr[arr.len() - 1];
                    }
                } else {
                    if let Node::Entry(e) = x {
                        return e.get_title().unwrap_or("") == arr[arr.len() - 1];
                    }
                }
                false
            })
            .unwrap_or(usize::MAX);

        if index == usize::MAX {
            return handle_not_found(socket);
        }

        g.children.remove(index);

        #[cfg(feature = "save_kdbx4")]
        db.save(
            &mut File::create(read_config()?)?,
            DatabaseKey::with_password(key.as_str().clone()),
        )?;

        socket.write_fmt(format_args!(
            "{}",
            "[-] Entry removed !!!\n".to_string().green(),
        ))?;
        return Ok(());
    }

    handle_not_found(socket)
}

fn handle_stop(socket: &mut UnixStream, status: &str) -> Result<()> {
    socket.write_fmt(format_args!(
        "{}\n",
        format!("[-] Daemon {} !!!", status).to_string().green(),
    ))?;
    socket.shutdown(Shutdown::Both)?;
    Ok(())
}

fn handle_listener(listener: &UnixListener, db: &mut Database, key: String) -> Result<bool> {
    let (mut socket, _addr) = listener.accept()?;
    let mut response = String::new();
    socket.read_to_string(&mut response)?;

    handle_wrap_search_rule!(socket, db, response.clone(), "show", handle_show);
    handle_wrap_search_rule!(socket, db, response.clone(), "copy", handle_copy);
    handle_wrap_search_rule!(socket, db, response.clone(), "pass", handle_pass);
    if response == "list" {
        handle_list(&mut socket, &db)?;
    } else if response.starts_with("add") {
        handle_add(&mut socket, db, key, response.replacen("add ", "", 1))?;
    } else if response.starts_with("rem") {
        handle_rem(&mut socket, db, key, response.replacen("rem ", "", 1))?;
    } else if response.starts_with("reload") {
        handle_stop(&mut socket, "reloaded")?;
        return Ok(false);
    } else if response.starts_with("stop") {
        handle_stop(&mut socket, "stopped")?;
        return Ok(false);
    }

    socket.shutdown(Shutdown::Both)?;
    Ok(true)
}

fn handle_timeout() -> Result<()> {
    if let Ok(Fork::Child) = fork() {
        thread::sleep(Duration::from_secs(read_timeout()?));
        let mut stream = UnixStream::connect(*SOCKET)?;
        stream.write_fmt(format_args!("stop"))?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
    }
    Ok(())
}

fn handle_thread(mut db: Database, key: String) -> Result<()> {
    if let Ok(Fork::Child) = fork() {
        let socket = Path::new(SOCKET_PATH);
        // Delete old socket if necessary
        if socket.exists() {
            fs::remove_file(&socket)?;
        }

        // Bind to socket
        let listener = UnixListener::bind(&socket)?;

        loop {
            if let Ok(false) = handle_listener(&listener, &mut db, key.clone()) {
                return Ok(());
            };
        }
    }
    thread::spawn(|| handle_timeout());
    Ok(())
}

fn start_thread(kdbx_path: String) -> Result<()> {
    println!("[?] kdbx's password: ");
    let password = rpassword::read_password()?;
    let db = Database::open(
        &mut File::open(kdbx_path)?, // the database
        DatabaseKey::with_password(&password),
    )?;
    thread::spawn(|| handle_thread(db, password));
    thread::sleep(Duration::from_millis(100));
    Ok(())
}

fn run_command(kdbx_path: String, command: String) -> Result<()> {
    let mut stream = match UnixStream::connect(*SOCKET) {
        Ok(s) => s,
        Err(_e) => {
            start_thread(kdbx_path.clone())?;
            UnixStream::connect(*SOCKET)?
        }
    };

    stream.write_fmt(format_args!("{}", command))?;
    stream.shutdown(Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    print!("{response}");

    if command == "reload" {
        start_thread(kdbx_path)?;
        return Ok(());
    }

    Ok(())
}

fn read_config() -> Result<String> {
    let configfileexp = CONFIG_PATH.expand_home()?;
    let configfile = Path::new(&configfileexp);
    if !configfile.exists() {
        println!(
            "[-](Init) Config file not found, will be created at\n\t{}",
            configfileexp.to_str().unwrap_or("(not found)").cyan()
        );
        let configdirexp = CONFIG_DIR_PATH.expand_home()?;
        let configdir = Path::new(&configdirexp);
        if !configdir.exists() {
            fs::create_dir(configdir)?;
        }
    }

    let mut config = Ini::new();

    let _map = config.load(configfile);

    let mut kdbx_path = config.get("Path", "kdbx").unwrap_or("".to_string());
    if kdbx_path == "" {
        println!(
            "{}\n[?](Init) kdbx path: ",
            "[x] kdbx path is missing".red()
        );
        println!("[-](Init) Daemon timeout set to 120 sec");
        let path: String = read!();
        config.set("Path", "kdbx", Some(path.clone()));
        config.set("Daemon", "timeout", Some((*DEF_TIMEOUT).to_string()));
        kdbx_path = path;
        config.write(configfile)?;
    }

    let kdbx_path_exp = kdbx_path.expand_home()?;
    let kdbxfile = Path::new(&kdbx_path_exp);

    if !kdbxfile.exists() {
        return Err(anyhow!(
            ".kdbx file not found in\n\t{}",
            kdbx_path_exp.to_str().unwrap_or("(not found)").cyan()
        ));
    }

    Ok(kdbx_path_exp.to_str().unwrap_or("").to_string())
}

fn read_timeout() -> Result<u64> {
    let configfileexp = CONFIG_PATH.expand_home()?;
    let configfile = Path::new(&configfileexp);
    if !configfile.exists() {
        return Ok(*DEF_TIMEOUT);
    }
    let mut config = Ini::new();
    let _ = config.load(configfile);

    let timeout: u64 = config
        .get("Daemon", "timeout")
        .unwrap_or(DEF_TIMEOUT.to_string())
        .parse()
        .unwrap_or(*DEF_TIMEOUT) as u64;

    Ok(timeout)
}

fn create_menu() -> Result<ArgMatches> {
    let matches = Command::new("rkeepass")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("list").about("Display the list of passwords"))
        .subcommand(
            Command::new("show")
                .about("Display title, url, username and password")
                .arg(
                    Arg::new("entry")
                        .help("<Group>/Entry")
                        .action(ArgAction::Set)
                        .num_args(1),
                ),
        )
        .subcommand(
            Command::new("pass")
                .about("Display only the password in plaintext")
                .arg(
                    Arg::new("entry")
                        .help("<Group>/Entry")
                        .action(ArgAction::Set)
                        .num_args(1),
                ),
        )
        .subcommand(
            Command::new("copy")
                .about("Copy selected entry's password to clipboard")
                .arg(
                    Arg::new("entry")
                        .help("<Group>/Entry")
                        .action(ArgAction::Set)
                        .num_args(1),
                ),
        )
        .subcommand(
            Command::new("add")
                .about("Add entry")
                .arg(
                    Arg::new("entry")
                        .help("<Group(s)>/Entry")
                        .action(ArgAction::Set)
                        .required(true)
                        .num_args(1),
                )
                .arg(
                    Arg::new("url")
                        .long("url")
                        .help("Entry url")
                        .action(ArgAction::Set)
                        .num_args(1),
                )
                .arg(
                    Arg::new("username")
                        .long("username")
                        .help("Entry username")
                        .action(ArgAction::Set)
                        .num_args(1),
                )
                .arg(
                    Arg::new("password")
                        .long("pass")
                        .help("Entry password")
                        .action(ArgAction::Set)
                        .num_args(1),
                ),
        )
        .subcommand(
            Command::new("rem").about("Remove selected entry").arg(
                Arg::new("entry")
                    .help("<Group>/Entry")
                    .action(ArgAction::Set)
                    .num_args(1),
            ),
        )
        .subcommand(Command::new("reload").about("Reload the daemon"))
        .subcommand(Command::new("stop").about("Stop the daemon"))
        .get_matches();
    Ok(matches)
}

fn main() -> Result<()> {
    let matches = create_menu()?;
    let mut command: String;
    match matches.subcommand() {
        Some(("list", _arg_list)) => command = "list".to_string(),
        Some(("reload", _arg_list)) => command = "reload".to_string(),
        Some(("stop", _arg_list)) => command = "stop".to_string(),
        Some((cmd, arg_list)) => {
            let entry = get_arg!(arg_list, "entry");
            command = format!("{} {}", cmd, entry.as_str());

            if cmd == "add" {
                let url = get_arg!(arg_list, "url");
                let username = get_arg!(arg_list, "username");
                let mut password = get_arg!(arg_list, "password");
                if password == "" {
                    let pg = PasswordGenerator {
                        length: 32,
                        numbers: true,
                        lowercase_letters: true,
                        uppercase_letters: true,
                        symbols: false,
                        spaces: false,
                        exclude_similar_characters: false,
                        strict: true,
                    };
                    password = pg.generate_one().unwrap_or("".to_string());
                }

                command = format!("{}\n{}\n{}\n{}", command, url, username, password);
            }
        }
        _ => unreachable!(),
    }

    let kdbx_path = read_config()?;

    if let Err(e) = run_command(kdbx_path, command) {
        match e.downcast_ref() {
            Some(DatabaseKeyError::IncorrectKey) => {
                println!("{}", "[x] Incorrect key !!!\n".to_string().red());
            }
            Some(DatabaseKeyError::InvalidKeyFile) => {
                println!("{}", "[x] Invalid key file !!!\n".to_string().red());
            }
            _ => {
                println!("{}", format!("[x] {} !!!\n", e).red());
            }
        }
    }

    Ok(())
}
