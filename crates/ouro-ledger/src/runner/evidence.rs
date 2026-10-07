//! Post-admission best-effort transport. Admission itself never uses this path.
use super::*;
use crate::pending::{Completion, Journal};

pub(super) struct Evidence {
    run: RunRecord,
    dir: PathBuf,
    data: PathBuf,
    pub claim: ClaimedOwner,
    offline: bool,
    initialized: bool,
    pub local_exit_saved: bool,
    retry_at: Instant,
}
impl Evidence {
    pub fn new(options: &RunOptions, run: &RunRecord, claim: &ClaimedOwner) -> Result<Self> {
        let mut run = run.clone();
        run.owner = Some(crate::daemon::peer_identity(
            unsafe { libc::geteuid() },
            std::process::id(),
        )?);
        Ok(Self {
            dir: options.data.join("ledger").join(&run.run_id),
            data: options.data.clone(),
            run,
            claim: claim.clone(),
            offline: false,
            initialized: false,
            local_exit_saved: false,
            retry_at: Instant::now(),
        })
    }
    pub fn admitted(&mut self) -> Result<()> {
        if self.run.payload["evidence"] == "best-effort" {
            Journal::open(&self.dir)?
                .create(&self.run, self.run.owner.as_ref().expect("owner identity"))?;
            self.initialized = true;
        }
        Ok(())
    }
    fn disconnected(&mut self, client: &Client, problem: LedgerError) -> Result<()> {
        if !self.initialized || !client.transport_failed() {
            return Err(problem);
        }
        let journal = Journal::open(&self.dir)?;
        let mut state = journal.read(&self.run)?;
        state.outage()?;
        journal.save(&state)?;
        self.offline = true;
        self.retry_at = Instant::now() + Duration::from_millis(250);
        Ok(())
    }
    pub fn source(&mut self, client: &mut Client, event: &Value) -> Result<()> {
        if !self.offline {
            match client.append_source(&self.run.run_id, event, &self.claim.producer_token) {
                Ok(_) => return Ok(()),
                Err(problem) => self.disconnected(client, problem)?,
            }
        }
        let journal = Journal::open(&self.dir)?;
        let mut state = journal.read(&self.run)?;
        state.push(event.clone())?;
        journal.save(&state)
    }
    fn reconnect(&mut self, client: &mut Client) -> Result<bool> {
        if Instant::now() < self.retry_at {
            return Ok(false);
        }
        self.retry_at = Instant::now() + Duration::from_millis(250);
        let Ok(mut fresh) = Client::connect(&self.data) else {
            return Ok(false);
        };
        let claim = match fresh.claim_owner(&self.run.run_id) {
            Ok(claim) => claim,
            Err(_) if fresh.transport_failed() => return Ok(false),
            Err(problem) => return Err(problem),
        };
        match fresh.reconcile_pending(&self.run.run_id) {
            Ok(_) => {}
            Err(_) if fresh.transport_failed() => return Ok(false),
            Err(problem) => return Err(problem),
        }
        *client = fresh;
        self.claim = claim;
        self.offline = false;
        Ok(true)
    }
    pub fn heartbeat(&mut self, client: &mut Client) -> Result<()> {
        if self.offline {
            self.reconnect(client)?;
        } else if let Err(problem) = client.ping() {
            self.disconnected(client, problem)?;
        }
        Ok(())
    }
    pub fn finish(
        &mut self,
        client: &mut Client,
        kind: &str,
        body: Value,
        control: ControlMessage,
    ) -> Result<()> {
        if self.initialized {
            let journal = Journal::open(&self.dir)?;
            let mut state = journal.read(&self.run)?;
            state.completion = Some(Completion {
                kind: kind.into(),
                body: body.clone(),
                control,
            });
            // No success acknowledgement can precede this local exit fence.
            journal.save(&state)?;
            self.local_exit_saved = true;
        }
        if !self.offline {
            match client.append_owner(
                &self.run.run_id,
                "settlement",
                kind,
                None,
                &body,
                &self.claim.owner_token,
            ) {
                Ok(_) => {
                    if self.initialized {
                        Journal::open(&self.dir)?.remove()?;
                    }
                    return Ok(());
                }
                Err(problem) => self.disconnected(client, problem)?,
            }
        }
        self.retry_at = Instant::now();
        if self.reconnect(client)? {
            return Ok(());
        }
        Err(error(
            "local exit recorded; canonical reconciliation is pending writer availability",
        ))
    }
}
