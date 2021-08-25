use color_eyre::eyre::WrapErr;
use crossbeam::channel::Receiver;
use crossbeam::channel::Sender;
use futures::future::BoxFuture;
use futures::lock::Mutex;
use futures::task::ArcWake;
use futures::task::Context;
use futures::FutureExt;
use rcgen::Certificate;
use rustls::Session;
use std::future::Future;
use std::io::Read;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::task::Poll;

use clap::Clap;
use color_eyre::Result;

#[derive(Clap, Clone)]
struct GemServerArgs {
    addr: SocketAddr,
}

/// Our async executor.
struct EventLoop {
    ready_queue: Receiver<Arc<Task>>,
}

impl EventLoop {
    async fn run(&self) {
        while let Ok(task) = self.ready_queue.recv() {
            let mut future_slot = task.future.lock().await;
            if let Some(mut future) = future_slot.take() {
                let waker = futures::task::waker_ref(&task);
                let context = &mut Context::from_waker(&*waker);
                if let Poll::Pending = future.as_mut().poll(context) {
                    future_slot.replace(future);
                }
            }
        }
    }
}

struct Task {
    future: Mutex<Option<BoxFuture<'static, ()>>>,
    task_sender: Sender<Arc<Task>>,
}

impl ArcWake for Task {
    fn wake_by_ref(arc: &std::sync::Arc<Self>) {
        let cloned = arc.clone();
        arc.task_sender.send(cloned).unwrap()
    }
}

struct Spawner {
    sender: Sender<Arc<Task>>,
}

impl Spawner {
    fn spawn(&self, future: impl Future<Output = ()> + 'static + Send) {
        let future = future.boxed();
        let task = Arc::new(Task {
            future: Mutex::new(Some(future)),
            task_sender: self.sender.clone(),
        });
        self.sender.send(task).unwrap();
    }
}

struct Client {
    socket: TcpStream,
    addr: SocketAddr,
    buf: [u8; 1028],
    tls_conn: rustls::ServerSession,
}

#[derive(Debug)]
pub struct Request(url::Url);

impl Client {
    fn read(&mut self) -> Option<Request> {
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(err) => {
                if let std::io::ErrorKind::WouldBlock = err.kind() {
                    return None;
                }
                panic!("Read error");
            }
            Ok(0) => {
                panic!("EOF;");
            }
            Ok(_) => {}
        }
        println!("{}", self.tls_conn.is_handshaking());
        // Read and process all available plaintext.
        if let Ok(()) = self.tls_conn.process_new_packets() {
            let mut buf = Vec::new();
            self.tls_conn.read(&mut buf).unwrap();
            let s = String::from_utf8(buf);
            println!("plaintext read {:?}", s);
        }
        None
    }
}

fn generate_localhost_certs() -> Result<Certificate> {
    extern crate rcgen;
    use rcgen::generate_simple_self_signed;
    // Generate a certificate that's valid for "localhost" and "hello.world.example"
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

    generate_simple_self_signed(subject_alt_names)
        .wrap_err_with(|| color_eyre::eyre::eyre!("Couldn't generate self signed certificate."))
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = GemServerArgs::parse();
    let tls_config = Arc::new(rustls::ServerConfig::new(Arc::new(rustls::NoClientAuth)));

    let listener = TcpListener::bind(args.addr)?;
    let (event_loop, spawner) = {
        let (tx, rx) = crossbeam::channel::unbounded();
        let event_loop = EventLoop { ready_queue: rx };
        let spawner = Spawner { sender: tx };
        (event_loop, spawner)
    };
    std::thread::spawn(move || loop {
        let (socket, addr) = listener.accept().unwrap();
        let tls_conn = rustls::ServerSession::new(&tls_config);
        let client = Client {
            socket,
            addr,
            tls_conn,
            buf: [0; 1028],
        };
        spawner.spawn(handle_client(client));
    });
    futures::executor::block_on(event_loop.run());
    Ok(())
}

async fn handle_client(mut client: Client) {
    loop {
        let msg = client.read();
        println!("{:?}", msg);
    }
}
