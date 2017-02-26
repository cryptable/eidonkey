extern crate hyper;
extern crate openssl;

use std::sync::Mutex;
use std::sync::Arc;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::Duration;
use hyper::net::{SslServer, NetworkStream};
use openssl::error::ErrorStack;
use openssl::ssl::{self, SslMethod, SslAcceptor, SslAcceptorBuilder};
use openssl::pkey::PKey;
use openssl::x509::X509Ref;

#[derive(Clone)]
pub struct HttpsServer(SslAcceptor);

impl HttpsServer {
    pub fn from_memory(key: &PKey, cert: &X509Ref, ca: &X509Ref) -> Result<HttpsServer, ErrorStack>
    {
        let chain = vec![ca];
        let mut ssl = try!(SslAcceptorBuilder::mozilla_modern(SslMethod::tls(), key, cert, chain));
        Ok(HttpsServer(ssl.build()))
    }
}

impl From<SslAcceptor> for HttpsServer {
    fn from(acceptor: SslAcceptor) -> HttpsServer {
        HttpsServer(acceptor)
    }
}

impl<T> SslServer<T> for HttpsServer
    where T: NetworkStream + Clone + Sync + Send + Debug
{
    type Stream = SslStream<T>;

    fn wrap_server(&self, stream: T) -> hyper::Result<SslStream<T>> {
        match self.0.accept(stream) {
            Ok(stream) => Ok(SslStream(Arc::new(Mutex::new(stream)))),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SslStream<T>(Arc<Mutex<ssl::SslStream<T>>>);

impl<T: Read + Write> Read for SslStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
}

impl<T: Read + Write> Write for SslStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

impl<T: NetworkStream> NetworkStream for SslStream<T> {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.0.lock().unwrap().get_mut().peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().unwrap().get_ref().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().unwrap().get_ref().set_write_timeout(dur)
    }
}
