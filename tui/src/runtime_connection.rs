//! Runtime discovery and ownership travel together; cleanup is explicit and asynchronous.
use super::*;

pub struct RuntimeConnection {
    pub publication: Publication,
    pub token: Secret,
    pub ownership: Ownership,
}

impl RuntimeConnection {
    pub fn attached(publication: Publication, token: Secret) -> Self {
        Self {
            publication,
            token,
            ownership: Ownership::Attached,
        }
    }
    pub fn spawned(publication: Publication, token: Secret, daemon: Daemon) -> Self {
        Self {
            publication,
            token,
            ownership: Ownership::Spawned(Box::new(daemon)),
        }
    }
}

pub enum Ownership {
    Attached,
    Spawned(Box<Daemon>),
}

impl Ownership {
    pub fn mode(&self) -> Mode {
        match self {
            Self::Attached => Mode::Attached,
            Self::Spawned(daemon) => Mode::Spawned { pid: daemon.pid() },
        }
    }
    pub fn owned(&self) -> Option<&Daemon> {
        match self {
            Self::Attached => None,
            Self::Spawned(daemon) => Some(daemon),
        }
    }
    pub fn owned_mut(&mut self) -> Option<&mut Daemon> {
        match self {
            Self::Attached => None,
            Self::Spawned(daemon) => Some(daemon),
        }
    }
    pub fn into_spawned(self) -> Option<Daemon> {
        match self {
            Self::Attached => None,
            Self::Spawned(daemon) => Some(*daemon),
        }
    }
    pub fn detach_with_notice(&mut self) {
        if let Self::Spawned(mut daemon) = std::mem::replace(self, Self::Attached) {
            let pid = daemon.pid();
            daemon.detach();
            eprintln!("the runtime is still running (pid {pid}); `ouro` attaches to it");
        }
    }
    pub async fn clean_up_after_error(
        &mut self,
        error: anyhow::Error,
        activity: &str,
    ) -> anyhow::Error {
        match std::mem::replace(self, Self::Attached) {
            Self::Attached => error,
            Self::Spawned(mut daemon) => {
                clean_up_daemon_after_error(&mut daemon, error, activity).await
            }
        }
    }

    /// Execute the quit choice using acknowledged shutdown, then bounded OS cleanup.
    pub async fn finish(self, quit: Quit, client: &Client, hello: &Hello) -> Result<()> {
        let Self::Spawned(mut daemon) = self else {
            client.stop().await;
            println!("disconnected; the runtime keeps running");

            return Ok(());
        };

        match quit {
            Quit::Detach | Quit::Disconnect => {
                let pid = daemon.pid();
                daemon.detach();
                println!("detached; the runtime is still running (pid {pid})");
            }
            Quit::Shutdown | Quit::ApplyFleetIntent => {
                if hello.serves("runtime.shutdown") && hello.operates() {
                    match client.call("runtime.shutdown", json!({})).await {
                        Ok(_result) => println!("the runtime accepted runtime.shutdown"),
                        // The runtime stopping is what was asked for, and it may stop before
                        // it can answer.
                        Err(ClientError::ConnectionClosed) => {
                            println!(
                                "the runtime accepted runtime.shutdown and closed the connection"
                            )
                        }
                        Err(error) => {
                            println!("runtime.shutdown failed ({error}); signalling instead")
                        }
                    }
                } else {
                    println!(
                    "this build does not serve runtime.shutdown at this scope; signalling pid {}",
                    daemon.pid()
                );
                }

                client.stop().await;

                match daemon.terminate(SHUTDOWN_GRACE).await? {
                    Some(status) => println!("the runtime exited: {status}"),
                    None => println!("the runtime had already exited"),
                }
            }
        }

        Ok(())
    }
}
