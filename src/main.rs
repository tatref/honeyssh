mod fake_shell;

use log::{debug, error, info};
use russh::server::{Auth, Session};
use russh::*;
use russh_keys::key::PublicKey;
use russh_keys::*;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::fake_shell::FakeShell;

// Dump path relative to CWD
const DUMP_DIR: &str = "dumps";

#[derive(Debug)]
struct HoneyError;

impl From<russh::Error> for HoneyError {
    fn from(_: russh::Error) -> Self {
        HoneyError
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    std::fs::create_dir_all(DUMP_DIR).expect("Unable to create dump dir");

    info!("Dump path: {}", DUMP_DIR);

    let args: Vec<_> = env::args().collect();
    if args.len() == 1 {
        error!("Usage: ./honeyssh <listen socket>");
        error!("Usage: ./honeyssh 192.168.0.1:2222");
        panic!("USAGE");
    }

    let socket: SocketAddr = args[1].parse().expect("Can't parse socket");
    info!("Listening on {:?}", socket);

    let mut config = russh::server::Config {
        server_id: SshId::Raw("SSH-2.0-OpenSSH_7.2p2".into()),
        connection_timeout: Some(std::time::Duration::from_secs(10)),
        auth_rejection_time: std::time::Duration::from_millis(100),
        ..Default::default()
    };

    let server_key =
        load_secret_key("./server_keys/id_ed25519", None).expect("Unable to load secret key");
    config.keys.push(server_key);

    let honeyserver = HoneyServer::new();

    russh::server::run(Arc::new(config), &socket, honeyserver)
        .await
        .unwrap();
}

struct HoneyServer {
    counter: u32,
}

impl HoneyServer {
    fn new() -> Self {
        Self { counter: 0 }
    }
}

impl russh::server::Server for HoneyServer {
    type Handler = HoneyHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        self.counter += 1;

        HoneyHandler::new(
            self.counter,
            peer_addr.expect("Didn't receive a remote address?"),
        )
    }
}

#[derive(Debug, Clone, Serialize)]
enum Event {
    ReceiveData(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
struct TimedEvent {
    time: Duration,
    event: Event,
}

struct HoneyHandler {
    id: u32,
    start_time: std::time::SystemTime,

    white_list: Vec<russh_keys::key::PublicKey>,

    peer: SocketAddr,
    user: Option<String>,
    password: Option<String>,
    accepted_key: Option<PublicKey>,
    sniffed: HashMap<ChannelId, Vec<TimedEvent>>,

    shell: FakeShell,
}

impl Serialize for HoneyHandler {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("Color", 3)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("start_time", &self.start_time)?;
        state.serialize_field("peer", &self.peer)?;
        state.serialize_field("user", &self.user)?;
        state.serialize_field("password", &self.password)?;
        if let Some(key) = &self.accepted_key {
            state.serialize_field("accepted_key", &key.fingerprint())?;
        }
        state.serialize_field("sniffed", &self.sniffed)?;
        state.end()
    }
}

impl HoneyHandler {
    fn new(id: u32, peer: SocketAddr) -> Self {
        info!("Connection from {:?}", peer);

        let mut white_list = Vec::new();

        for entry in glob::glob("./client_keys/*.pub").expect("Can't read client_keys dir") {
            white_list.push(
                load_public_key(entry.expect("Can't read pubkey file"))
                    .expect("Can't load pub key"),
            );
        }

        let start_time = SystemTime::now();

        Self {
            id,
            start_time,
            white_list,
            peer,
            user: None,
            password: None,
            accepted_key: None,
            shell: FakeShell::new(),
            sniffed: HashMap::new(),
        }
    }
}

impl Drop for HoneyHandler {
    fn drop(&mut self) {
        let f_name = Path::new(DUMP_DIR).join(format!("{}", self.id));

        let mut file = File::create(f_name).unwrap();
        file.write_all(
            format!(
                "id: {:?}, peer: {:?}, user: {:?}, password: {:?}\n",
                self.id, self.peer, self.user, self.password
            )
            .as_bytes(),
        )
        .unwrap();

        let s = serde_json::to_vec(&self.sniffed).expect("Can't serialize sniffed data");
        file.write_all(&s).unwrap()
    }
}

impl russh::server::Handler for HoneyHandler {
    type Error = HoneyError;
    type FutureAuth = futures::future::Ready<Result<(Self, server::Auth), Self::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, server::Session), Self::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, server::Session, bool), Self::Error>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        info!("finished_auth: {:?}", auth);
        futures::future::ready(Ok((self, auth)))
    }
    fn finished_bool(self, b: bool, session: Session) -> Self::FutureBool {
        info!("finished_bool");
        futures::future::ready(Ok((self, session, b)))
    }
    fn finished(self, session: Session) -> Self::FutureUnit {
        info!("finished");
        futures::future::ready(Ok((self, session)))
    }
    fn auth_none(mut self, user: &str) -> Self::FutureAuth {
        info!("auth_none");

        self.user = Some(String::from(user));

        self.finished_auth(server::Auth::Reject {
            proceed_with_methods: None,
        })
    }
    fn auth_password(mut self, user: &str, password: &str) -> Self::FutureAuth {
        info!("auth password");

        self.user = Some(String::from(user));
        self.password = Some(String::from(password));

        self.finished_auth(server::Auth::Accept)
    }
    fn auth_publickey(
        mut self,
        user: &str,
        publickey: &russh_keys::key::PublicKey,
    ) -> Self::FutureAuth {
        info!("auth_publickey");

        self.user = Some(String::from(user));

        let mut auth_ok = false;
        for white_listed_key in &self.white_list {
            if publickey == white_listed_key {
                info!("auth_publickey: accepted key {}", publickey.fingerprint());
                self.accepted_key = Some(publickey.clone());
                auth_ok = true;
            }
        }

        if auth_ok {
            self.finished_auth(server::Auth::Accept)
        } else {
            self.finished_auth(server::Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }
    fn auth_keyboard_interactive(
        mut self,
        user: &str,
        _submethods: &str,
        _response: Option<russh::server::Response>,
    ) -> Self::FutureAuth {
        info!("auth_keyboard_interactive");

        self.user = Some(String::from(user));

        self.finished_auth(server::Auth::Reject {
            proceed_with_methods: None,
        })
    }
    fn channel_close(self, _channel: ChannelId, session: Session) -> Self::FutureUnit {
        info!("channel_close");

        self.finished(session)
    }
    fn channel_eof(self, channel: ChannelId, mut session: Session) -> Self::FutureUnit {
        info!("channel_eof");
        self.finished(session)
    }

    fn channel_open_session(
        self,
        channel: ChannelId,
        session: server::Session,
    ) -> Self::FutureBool {
        info!("{}: channel_open_session", self.id);

        self.finished_bool(true, session)
    }
    fn data(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: server::Session,
    ) -> Self::FutureUnit {
        debug!(
            "data on channel {:?}: {:?}",
            channel,
            std::str::from_utf8(data)
        );

        let event = TimedEvent {
            time: self.start_time.elapsed().expect("Can't compute delta time"),
            event: Event::ReceiveData(Vec::from(data)),
        };
        self.sniffed.entry(channel).or_default().push(event);

        let result = self.shell.feed(data);
        session.data(channel, CryptoVec::from_slice(&result));

        self.finished(session)
    }

    fn channel_open_x11(
        self,
        channel: ChannelId,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureBool {
        info!("{}: channel_open_x11", self.id);
        self.finished_bool(true, session)
    }

    fn channel_open_direct_tcpip(
        self,
        channel: ChannelId,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureBool {
        info!("{}: channel_open_direct_tcpip", self.id);
        self.finished_bool(true, session)
    }

    fn extended_data(
        self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: Session,
    ) -> Self::FutureUnit {
        info!("{}: extended_data", self.id);
        self.finished(session)
    }

    fn window_adjusted(
        self,
        channel: ChannelId,
        new_window_size: usize,
        session: Session,
    ) -> Self::FutureUnit {
        info!("{}: window_adjusted", self.id);
        //if let Some(ref mut enc) = session.common.encrypted {
        //    enc.flush_pending(channel);
        //}
        self.finished(session)
    }

    fn adjust_window(&mut self, channel: ChannelId, current: u32) -> u32 {
        info!("{}: adjust_window", self.id);
        current
    }

    fn pty_request(
        self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: Session,
    ) -> Self::FutureUnit {
        info!("{}: pty_request", self.id);
        self.finished(session)
    }

    fn x11_request(
        self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: Session,
    ) -> Self::FutureUnit {
        info!("{}: x11_request", self.id);
        self.finished(session)
    }

    fn env_request(
        self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: Session,
    ) -> Self::FutureUnit {
        info!(
            "{}: env_request: {}={}",
            self.id, variable_name, variable_value
        );
        self.finished(session)
    }

    fn shell_request(mut self, channel: ChannelId, mut session: Session) -> Self::FutureUnit {
        info!("{}: shell_request", self.id);
        self.shell = FakeShell::new();
        let result = self.shell.feed(b"\r");
        session.data(channel, CryptoVec::from_slice(&result));

        self.finished(session)
    }

    fn subsystem_request(
        self,
        channel: ChannelId,
        name: &str,
        session: Session,
    ) -> Self::FutureUnit {
        info!("{}: subsystem_request", self.id);
        self.finished(session)
    }

    fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: Session,
    ) -> Self::FutureUnit {
        info!("{}: window_change_request", self.id);
        self.finished(session)
    }

    fn signal(self, channel: ChannelId, signal_name: Sig, session: Session) -> Self::FutureUnit {
        info!("{}: signal", self.id);
        self.finished(session)
    }

    fn tcpip_forward(self, address: &str, port: u32, session: Session) -> Self::FutureBool {
        info!("{}: tcpip_forward", self.id);
        self.finished_bool(false, session)
    }

    fn cancel_tcpip_forward(self, address: &str, port: u32, session: Session) -> Self::FutureBool {
        info!("{}: cancel_tcpip_forward", self.id);
        self.finished_bool(false, session)
    }
}
