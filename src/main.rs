extern crate thrussh;
extern crate thrussh_keys;
extern crate futures;
extern crate tokio_core;
extern crate ring;
extern crate glob;

#[macro_use] extern crate log;
extern crate env_logger;

use glob::glob;

use futures::{Stream,Future};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_core::net::TcpListener;
use tokio_core::reactor::{Core};

use thrussh::*;
use thrussh::server::Config;
use thrussh::server::Connection;
use thrussh::server::Handler;
use thrussh::server::Server;
use thrussh::server::Auth;
use thrussh::server::Session;
use thrussh::server::Response;
use thrussh_keys::key::PublicKey;



const DUMP_DIR: &'static str = "dump";


//#[derive(Clone)]
struct HoneyHandler {
    socket: SocketAddr,

    white_list: Vec<PublicKey>,

    user: Option<String>,
    password: Option<String>,
    sniffed: Vec<u8>,
}


impl HoneyHandler {
    fn new(socket: SocketAddr) -> Self {
        use thrussh_keys::load_public_key;

        let mut white_list = Vec::new();

        for entry in glob("./client_keys/*.pub").unwrap() {
            match entry {
                Ok(ref path) => white_list.push(load_public_key(path).unwrap()),
                Err(e) => error!("Unable to load public key: {:?}", e),
            }
        }

        Self {
            socket,
            white_list,
            user: None,
            password: None,
            sniffed: Vec::new(),
        }
    }

    fn get_prompt() -> &'static [u8] {
        b"[root@debian ~]$ "
    }

}

impl Drop for HoneyHandler {
    fn drop(&mut self) {
        use std::fs::File;
        use std::path::Path;
        use std::io::prelude::*;

        let f_name = match self.socket {
            SocketAddr::V4(sock) => format!("{}.txt", sock),
            SocketAddr::V6(sock) => format!("{}.txt", sock),
        };

        let f_name = Path::new(DUMP_DIR).join(f_name);

        let mut file = File::create(f_name).unwrap();
        file.write_all(format!("user: {:?}, password: {:?}\n", self.user, self.password).as_bytes()).unwrap();
        file.write_all(&self.sniffed).unwrap()
    }
}

impl Handler for HoneyHandler {
	type Error = ();
	type FutureAuth = futures::Finished<(Self, server::Auth), Self::Error>;
	type FutureUnit = futures::Finished<(Self, server::Session), Self::Error>;
	type FutureBool = futures::Finished<(Self, server::Session, bool), Self::Error>;

	fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        info!("finished_auth: {:?}", auth);
		futures::finished((self, auth))
	}
	fn finished_bool(self, session: Session, b: bool) -> Self::FutureBool {
        info!("finished_bool");
		futures::finished((self, session, b))
	}
	fn finished(self, session: Session) -> Self::FutureUnit {
        info!("finished");
		futures::finished((self, session))
	}
    fn auth_none(mut self, user: &str) -> Self::FutureAuth {
        info!("auth_none");

        self.user = Some(String::from(user));

		futures::finished((self, server::Auth::Reject))
    }
	fn auth_password(mut self, user: &str, password: &str) -> Self::FutureAuth {
        info!("auth password");

        self.user = Some(String::from(user));
        self.password = Some(String::from(password));

		futures::finished((self, server::Auth::Accept))
	}
	fn auth_publickey(mut self, user: &str, publickey: &PublicKey) -> Self::FutureAuth {
        info!("auth_publickey");

        self.user = Some(String::from(user));

        let mut auth_ok = false;
        for white_listed_key in &self.white_list {
            if &publickey == &white_listed_key {
                info!("auth_publickey: Accepted!");
                auth_ok = true;
            }
        }

        if auth_ok {
            futures::finished((self, server::Auth::Accept))
        }
        else {
            futures::finished((self, server::Auth::Reject))
        }
	}
    fn auth_keyboard_interactive(mut self, user: &str, _submethods: &str, _response: Option<Response>) -> Self::FutureAuth {
        info!("auth_keyboard_interactive");

        self.user = Some(String::from(user));

        futures::finished((self, server::Auth::Reject))
    }
    fn channel_close(self, _channel: ChannelId, _session: Session) -> Self::FutureUnit
    {
        info!("channel_close");

        futures::finished((self, _session))
    }
    fn channel_eof(self, _channel: ChannelId, _session: Session) -> Self::FutureUnit {
        info!("channel_eof");
        futures::finished((self, _session))
    }

    fn channel_open_session(self, channel: ChannelId, mut session: server::Session) -> Self::FutureUnit {
        info!("Session opened!");
        session.data(channel, None, Self::get_prompt());

        futures::finished((self, session))
    }
	fn data(mut self, channel: ChannelId, data: &[u8], mut session: server::Session) -> Self::FutureUnit {
		info!("{:?}: data on channel {:?}: {:?}", self.socket, channel, std::str::from_utf8(data));

        self.sniffed.push(data[0].clone());

        match data {
            b"\r" => {
                // line break
                session.data(channel, None, b"\r\n");
                session.data(channel, None, Self::get_prompt());
            },
            _ => {
                // copy data back to sender
                session.data(channel, None, data);
            },
        }

		futures::finished((self, session))
	}
}

struct HoneyServer {
}

impl Server for HoneyServer {
    type Handler = HoneyHandler;

    fn new(&self, addr: SocketAddr) -> Self::Handler {
        HoneyHandler::new(addr)
    }
}

fn run<S: Server + 'static>(config: Arc<Config>, addr: &str, server: S) {
    let addr = addr.parse::<std::net::SocketAddr>().unwrap();
    let mut l = Core::new().unwrap();
    let handle = l.handle();
    let socket = TcpListener::bind(&addr, &handle).unwrap();
    info!("Listening on {:?}", socket);

    let done = socket.incoming().for_each(move |(socket, addr)| {
        info!("Incoming: {:?}", socket);

        let handler = server.new(addr);
        let connection = Connection::new(config.clone(), handle.clone(), socket, handler).unwrap();
        handle.spawn(connection.map_err(|err| error!("err {:?}", err)));
        Ok(())
    });
    l.run(done).unwrap();
}



fn main() {
    env_logger::init().expect("Unable to initialize logger");

    std::fs::create_dir_all(DUMP_DIR).expect("Unable to create dump dir");


    use std::env;
    use thrussh_keys::load_secret_key;

    let args: Vec<_> = env::args().collect();

    if args.len() == 1 {
        error!("Usage: ./honeyssh <listen socket>");
        error!("Usage: ./honeyssh 192.168.0.1:2222");
        return;
    }

    let socket = &args[1];


	let mut config = thrussh::server::Config::default();
	config.connection_timeout = Some(std::time::Duration::from_secs(600));
	config.auth_rejection_time = std::time::Duration::from_secs(10);

    let server_key = load_secret_key("./server_keys/id_ed25519", None)
        .expect("Unable to load secret key");
    config.keys.push(server_key);

	let honeyserver = HoneyServer {};

	run(Arc::new(config), socket, honeyserver);

}
