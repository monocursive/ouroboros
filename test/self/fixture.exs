defmodule Ouroboros.Self.Fixture do
  @moduledoc """
  A real signed policy component, live on a register a test owns (S4).

  `test/wasm/policy_promotion_test.exs`' harness, lifted into a module both S4 suites can
  call: the export has to assemble a bundle out of a store, and the boot has to deploy one
  into a different store, and neither claim means anything against a hand-written manifest.
  So this signs the guest SDK's `no-network-shell` with a real
  `Ouroboros.Upgrade.Signing.Service`, deploys it through the real `Ouroboros.Wasm.Rollout`
  — probe, evaluate and settle, against this machine's own `ouro-wasm` — and hands back the
  registry, the store root, the pool and the trust policy that made it work.

  Required at the top of both suites with `Code.require_file/2`, which is idempotent, rather
  than living in `test/support/`: it is S4's fixture and nothing outside S4 has a use for it.

  A top-level module on purpose. A `defmodule` nested inside a test module takes that
  module's prefix and shadows every alias whose last segment matches.
  """

  import ExUnit.Callbacks, only: [start_supervised!: 2, on_exit: 1]

  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm.{Artifact, LiveFixture, Pool, Rollout, SandboxFixture}

  @component Path.expand(
               "../../tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm",
               __DIR__
             )

  # S4 fix wave (MEDIUM-2). The other kind of thing a `priv/self` could hold: a real,
  # really-signed **capability**, which the boot must skip because of what it is.
  @capability Path.expand(
                "../../tui/wasm/guest/examples/counter/target/wasm32-wasip2/release/counter.wasm",
                __DIR__
              )

  # `policy_acp_test.exs`' signed test story, verbatim: one case per direction of what the
  # component claims to do, run against the real component at deploy.
  @eval %{
    cases: [
      %{
        request: %{"tool" => "bash", "input" => %{"command" => "curl https://example.test"}},
        expect: %{decision: :deny}
      },
      %{
        request: %{"tool" => "bash", "input" => %{"command" => "ls -la"}},
        expect: %{decision: :ask}
      }
    ],
    budget_ms: 20_000
  }

  @doc "The policy component this fixture signs, and the tag a suite needing it carries."
  def component, do: @component

  @doc "The `@tag` for a test that needs the real helper and the built guest."
  def tag, do: LiveFixture.tag(@component)

  @doc "What `setup_all` runs so a required run fails rather than skips."
  def ensure! do
    if LiveFixture.required?() do
      LiveFixture.ensure!()

      for path <- [@component, @capability] do
        unless File.regular?(path) do
          raise "OUROBOROS_REQUIRE_WASM is set and there is no #{path}; `make wasm-examples`"
        end
      end
    end

    :ok
  end

  @doc """
  Signs `no-network-shell` and deploys it live into a store and register of this test's own.

  `signer` names the identity, so a suite can produce a bundle signed by a key the receiving
  node does not trust simply by using a different one. Returns the whole world the deploy
  happened in.
  """
  def live_policy!(tmp, signer \\ "self-export-key") do
    %{service: service, trust_policy: trust_policy} = signing!(tmp, signer)
    trust!(trust_policy)

    registry = registry!()
    store_root = Path.join(tmp, "store-#{System.unique_integer([:positive])}")
    pool = pool!(tmp)

    bytes = File.read!(@component)
    {:ok, epoch} = Epoch.next([node()])

    {:ok, artifact} =
      Artifact.build(bytes,
        name: "no-network-shell",
        epoch: epoch,
        kind: :policy,
        imports: ["log"],
        author: "self-export-test",
        eval: @eval
      )

    {:ok, value} =
      Service.sign_artifact(
        artifact,
        signer,
        %{
          requester: node(),
          payload: Artifact.signing_payload(artifact, signer),
          component_bytes: bytes
        },
        service
      )

    {:ok, signed} = Artifact.with_signature(artifact, %{signer: signer, value: value})

    {:ok, outcome} =
      Rollout.deploy(signed, bytes, [node()],
        registry: registry,
        store_root: store_root,
        trust_policy: trust_policy,
        pool: pool
      )

    :live = outcome.state

    %{
      artifact: signed,
      sha: signed.component_sha256,
      name: signed.name,
      signer: signer,
      service: service,
      registry: registry,
      store_root: store_root,
      pool: pool,
      trust_policy: trust_policy
    }
  end

  @doc "The `counter` example, and the tag a suite needing it carries."
  def capability_component, do: @capability

  @doc "The `@tag` for a test that needs the built `counter` capability beside the helper."
  def capability_tag, do: LiveFixture.tag(@capability)

  @doc """
  A real signed bundle whose `kind` is `:capability`, for a test about what does *not* ship.

  Signed by `live.service` under `live.signer`, so it is a bundle the receiving node's trust
  policy accepts — which is the point: what stops it is its kind and not its signature.
  Never deployed anywhere; the caller drops the bytes into a `priv/self` and boots it.
  """
  def capability_bundle!(live, name \\ "counter") do
    bytes = File.read!(@capability)
    {:ok, epoch} = Epoch.next([node()])

    {:ok, artifact} =
      Artifact.build(bytes,
        name: name,
        epoch: epoch,
        kind: :capability,
        imports: ["log"],
        author: "self-export-test",
        # A capability's eval spec is a probe list over the component's own state, and one is
        # required to sign at all under `signing_require_wasm_eval` — which this posture
        # asserts is on. Never replayed here: the point of this bundle is that it is refused
        # before anything about it is exercised.
        eval: %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 5_000}
      )

    {:ok, value} =
      Service.sign_artifact(
        artifact,
        live.signer,
        %{
          requester: node(),
          payload: Artifact.signing_payload(artifact, live.signer),
          component_bytes: bytes
        },
        live.service
      )

    {:ok, signed} = Artifact.with_signature(artifact, %{signer: live.signer, value: value})
    {:ok, bundle} = Ouroboros.Wasm.Bundle.encode(signed, bytes, nil)
    %{artifact: signed, bundle: bundle}
  end

  @doc """
  The same, deployed live with **no signature at all** (S4 fix wave, LOW-5).

  A node outside production may set `allow_unsigned: true` — `config/config.exs` does — and
  a rollout there accepts a manifest nobody signed. `Ouroboros.Self.Export` must still refuse
  to export it, because `signers.txt` is the line the receiving operator pastes and there is
  no key to write on it. This is the world where that refusal is the only thing standing.
  """
  def live_unsigned!(tmp) do
    trust_policy = [allow_unsigned: true, trusted_signers: %{}]
    trust!(trust_policy)

    registry = registry!()
    store_root = Path.join(tmp, "store-#{System.unique_integer([:positive])}")
    pool = pool!(tmp)

    bytes = File.read!(@component)
    {:ok, epoch} = Epoch.next([node()])

    {:ok, artifact} =
      Artifact.build(bytes,
        name: "no-network-shell",
        epoch: epoch,
        kind: :policy,
        imports: ["log"],
        author: "self-export-test",
        eval: @eval
      )

    {:ok, outcome} =
      Rollout.deploy(artifact, bytes, [node()],
        registry: registry,
        store_root: store_root,
        trust_policy: trust_policy,
        pool: pool
      )

    :live = outcome.state

    %{
      artifact: artifact,
      sha: artifact.component_sha256,
      name: artifact.name,
      registry: registry,
      store_root: store_root,
      pool: pool,
      trust_policy: trust_policy
    }
  end

  @doc "A signing service holding a fresh key, and the trust policy that accepts it."
  def signing!(tmp, signer) do
    key_path = Path.join(tmp, "signer-#{System.unique_integer([:positive])}.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           name: nil,
           key_path: key_path,
           signer_id: signer,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("self_journal_#{System.unique_integer([:positive])}")}
         ]},
        id: {Service, System.unique_integer([:positive])}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)

    %{
      service: service,
      public: public,
      key_path: key_path,
      trust_policy: [allow_unsigned: false, trusted_signers: %{signer => public}]
    }
  end

  @doc """
  Makes `trust_policy` this node's, restoring whatever was there when the test ends.

  It has to be application environment and not only an option: `Ouroboros.Wasm.Rollout`
  hands each **target** no policy at all, on purpose, so the node that stages a byte reads
  its own. A suite that only passed the option would be verifying the sender.

  Safe to call more than once — `on_exit` callbacks run in reverse registration order, so
  the first value saved is the last one restored.
  """
  def trust!(trust_policy) do
    saved = Application.get_env(:ouroboros, :upgrade_trust_policy)

    on_exit(fn ->
      case saved do
        nil -> Application.delete_env(:ouroboros, :upgrade_trust_policy)
        value -> Application.put_env(:ouroboros, :upgrade_trust_policy, value)
      end
    end)

    Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)
    trust_policy
  end

  @doc "An empty rollout register nothing else on this node shares."
  def registry! do
    name = String.to_atom("self_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("self_rollouts_#{System.unique_integer([:positive])}")}
      )

    on_exit(fn -> stop(pid) end)
    name
  end

  @doc "A helper pool fenced to this test's directory, spawning the real `ouro-wasm`."
  def pool!(dir) do
    name = :"self_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start([name: name, handshake_timeout_ms: 15_000] ++ SandboxFixture.pool_opts(dir))

    on_exit(fn -> stop(pid) end)
    pid
  end

  @doc "A promotion record of this test's own, so the node's is never touched."
  def promotion! do
    start_supervised!(
      {PolicyPromotion,
       [
         name: nil,
         storage:
           {Jido.Storage.ETS,
            table: String.to_atom("self_promotion_#{System.unique_integer([:positive])}")}
       ]},
      id: {PolicyPromotion, System.unique_integer([:positive])}
    )
  end

  @doc "The evidence shape `PolicyPromotion.promote/6` takes, with numbers a test can read."
  def evidence(decisions \\ 57, contradictions \\ 0) do
    %{
      report_sha256: String.duplicate("a", 64),
      decisions: decisions,
      contradictions: contradictions,
      replayed_at: "2026-09-08T00:00:00Z"
    }
  end

  @doc "A scratch directory removed when the test ends."
  def tmp!(prefix) do
    dir = Path.join(System.tmp_dir!(), "#{prefix}-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  defp stop(pid) do
    if Process.alive?(pid) do
      try do
        GenServer.stop(pid, :normal, 5_000)
      catch
        :exit, _reason -> :ok
      end
    end
  end
end
