defmodule Ouroboros.Upgrade.Signing.Key do
  @moduledoc """
  An Ed25519 keypair held in one process, wrapped so it does not fall out of a term.

  Inspect is overridden rather than derived-with-`:except`, because the failure this
  guards against is incidental: a crash report, a `Logger.error` on state, a debugging
  `IO.inspect`, an exception whose message interpolates the GenServer's state. All of
  those go through `Inspect`, and all of them would otherwise print a signing key.

  This is containment of accidents, not of the VM. Anything running on this node can
  read this struct's fields directly — `:sys.get_state/1` alone is enough. The boundary
  that matters is the one around the host: a signer node runs
  `Ouroboros.Upgrade.Signing.Service` and cluster formation and nothing else, and the
  key never leaves it. See the service's moduledoc for what that does and does not buy.
  """

  @enforce_keys [:signer_id, :public, :secret]
  defstruct @enforce_keys

  @type t :: %__MODULE__{signer_id: String.t(), public: binary(), secret: binary()}

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%{signer_id: signer_id}, opts) do
      concat([
        "#Ouroboros.Upgrade.Signing.Key<signer_id: ",
        to_doc(signer_id, opts),
        ", key: [REDACTED]>"
      ])
    end
  end
end

defmodule Ouroboros.Upgrade.Signing.Service do
  @moduledoc """
  The signing authority: a key, an independent policy, and a durable record, on a node
  whose supervision tree contains nothing else.

  `Ouroboros.Upgrade.Forge.Signer` describes the seam. This is the thing on the other
  side of it. The forge asks; this process decides, and it decides *before* a signature
  exists — which is the only moment at which refusing is free.

  ## What makes it independent

  Three properties, none of which are rhetorical:

    * **The key is not in the patchable application's reach.** It is read at boot from
      the file named by `OUROBOROS_SIGNER_KEY_PATH`, on a `:signer`-role node, and lives
      in this process's state. `Ouroboros.Upgrade.Forge.Signer.Local` — still shipped,
      still fine for a dev loop — reads its key from the configuration of the very
      application whose code it authorizes; an agent that can patch that application can
      read it. This service moves the key to a host with no teams, no stores, no
      sessions, no scheduler, and no control plane on it.
    * **The policy sees the whole artifact, not the payload.** A payload is a hash of
      claims. `Ouroboros.Upgrade.Signing.Policy` recomputes those claims from the BEAM
      bytes actually submitted and refuses anything outside `Ouroboros.Capability.`, so
      the structural guarantee "an agent cannot approve a patch to a control plane" is
      enforced by the absence of a code path rather than by anyone's discipline.
    * **Every decision is journaled before it is answered.** A signature is never
      returned unless the entry describing it is durably acknowledged first, and a
      journal that will not accept the entry is a refusal to sign. Refusals are
      journaled too; a log with only successes cannot tell "nobody asked" from
      "something asked two thousand times".

  ## Fail closed, from boot

  A `:signer` node with no readable key, an invalid key, no signer id, or an unusable
  journal **refuses to boot**, the way `Ouroboros.Cluster.boot_role!/0` refuses an
  unrecognized role. A signer that starts anyway and errors per request looks, from the
  outside, exactly like a signer that is deliberately denying — and the two need very
  different operator responses.

  ## The key file

  `OUROBOROS_SIGNER_KEY_PATH` names a file holding an Ed25519 **seed**: either 32 raw
  bytes, or the base64 of those 32 bytes (surrounding whitespace ignored). The public
  half is derived at boot and published by `public_info/0`, which also renders the exact
  `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` entry a core node needs:

      :erpc.call(:"signer-1@10.0.0.30", Ouroboros.Upgrade.Signing.Service, :public_info, [])
      #=> {:ok, %{signer_id: "release-key", public_key_base64: "...", trusted_signers_entry: "release-key:..."}}

  Key material is never logged, never inspected, never returned, and never journaled.
  `Ouroboros.Upgrade.Signing.Key` redacts itself under `Inspect` so a crash report cannot
  print it by accident.

  ## Honest limits

  This narrows custody. It does not achieve it.

    * A signer node is still a **connected cluster member**. Any node that completes the
      distribution handshake — cookie, and TLS if configured — can `:erpc` into this
      service exactly like the forge does. The policy runs in this process, so what such
      a node gets is a policy decision rather than a signature on demand; what it does
      not get is refused. TLS distribution and role isolation narrow that surface. They
      do not eliminate it.
    * A connected node with `:erpc` authority is not limited to this module's public
      API. Role isolation means there is little else on the host worth reaching, not
      that reaching is impossible.
    * The `requester` in every journal entry is **self-reported**. It is what the caller
      said, journaled as a claim. The per-requester rate limit therefore bounds
      accidents, retry storms, and honest clients — not an adversary who can vary it.
    * The policy proves the submitted bytes are internally consistent and namespaced. It
      cannot re-run a build it did not perform, so the link between `test_report` and
      those bytes is the forge's assertion, carried in signed metadata.
    * True air-gapped custody — a key on a host that is not a cluster member, reached
      over a narrow audited channel, with a human in it — remains external to this
      runtime. Nothing here is a substitute for it, and this docstring is not going to
      start implying otherwise.

  ## Configuration

    * `OUROBOROS_SIGNER_KEY_PATH` — the seed file. Required on a `:signer` node.
    * `config :ouroboros, :signer_id` (or `OUROBOROS_SIGNER_ID`) — the identity this
      service signs as. It must match the id in the signature envelope and in every core
      node's `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`; a request naming a different id is
      refused rather than silently signed under this one.
    * `config :ouroboros, :signing_journal_storage` — ETS in dev and test, a synced
      `Ouroboros.Storage.DurableFile` in production.
    * `config :ouroboros, :signing_policy` — the policy module.
    * `config :ouroboros, :signing_require_eval` — require a signed evaluation spec.
    * `config :ouroboros, :signing_rate_limit_per_minute` — admissions per requester.
    * `config :ouroboros, :signing_journal_limit` — decisions retained.
    * `config :ouroboros, :signing_max_artifact_bytes` — the largest submission accepted.
  """

  use GenServer

  require Logger

  alias Ouroboros.Upgrade.Artifact
  alias Ouroboros.Upgrade.Signing.{Journal, Key, Policy}

  @store_key {:ouroboros, :signing_journal, 1}
  @key_path_env "OUROBOROS_SIGNER_KEY_PATH"
  @signer_id_env "OUROBOROS_SIGNER_ID"
  @seed_bytes 32
  @default_rate_limit 30
  @default_max_artifact_bytes 16 * 1024 * 1024
  @call_timeout 15_000

  @type request :: %{optional(:requester) => node(), optional(:payload) => binary()}
  @type decision :: {:ok, binary()} | {:refused, term()}

  @doc """
  Starts the service.

  Options are for tests and for operators who supply configuration another way:
  `:name`, `:key_path`, `:signer_id`, `:storage`, `:policy`, `:require_eval`,
  `:rate_limit_per_minute`, `:journal_limit`, and `:max_artifact_bytes`. Everything
  omitted comes from the environment and application configuration.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Applies policy to `artifact` and, if it passes, returns a detached Ed25519 signature.

  This is the remote entry point: `Ouroboros.Upgrade.Forge.Signer.Remote` reaches it by
  `:erpc`. `request` is a plain map carrying `:requester` (the calling node, journaled as
  a claim) and optionally `:payload`.

  The `:payload` is **advisory**. The signature is always over bytes this service derives
  itself with `Ouroboros.Upgrade.Artifact.signing_payload/2` from the artifact in front
  of it; a caller's payload is never signed and never trusted. It is cross-checked, and a
  disagreement is refused — not because the signature would have been unsafe, but because
  the requester and the signer disagreeing about what is being signed is a version skew
  worth stopping at.

  Never raises: a service that is down, wedged, or missing is `{:refused, reason}` like
  any other outcome, because the caller reaches this through `:erpc` and an escaping
  exception there is indistinguishable from transport ambiguity.
  """
  @spec sign_artifact(Artifact.t(), String.t(), request(), GenServer.server()) :: decision()
  def sign_artifact(artifact, signer_id, request \\ %{}, server \\ __MODULE__) do
    if is_binary(signer_id) and signer_id != "" and is_map(request) do
      call(
        server,
        {:sign, artifact, signer_id, request},
        {:refused, :signing_service_unavailable}
      )
    else
      {:refused, {:invalid_signing_request, describe(signer_id)}}
    end
  end

  @doc """
  The public half of this signer's identity, for an operator to trust on a core node.

  Returns the signer id, the raw 32-byte Ed25519 public key, its base64 rendering, and
  the exact `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` entry those two make. Nothing here is
  secret; the private half has no accessor anywhere in this module.
  """
  @spec public_info(GenServer.server()) :: {:ok, map()} | {:error, term()}
  def public_info(server \\ __MODULE__) do
    call(server, :public_info, {:error, :signing_service_unavailable})
  end

  @doc "Every journaled decision, oldest first."
  @spec decisions(GenServer.server()) :: {:ok, [Journal.entry()]} | {:error, term()}
  def decisions(server \\ __MODULE__) do
    call(server, :decisions, {:error, :signing_service_unavailable})
  end

  @doc """
  What this signer is, without saying what it holds.

  Identity, durability level, decision counts, and how many requesters the rate limiter
  is currently tracking.
  """
  @spec status(GenServer.server()) :: {:ok, map()} | {:error, term()}
  def status(server \\ __MODULE__) do
    call(server, :status, {:error, :signing_service_unavailable})
  end

  @doc false
  @spec checkpoint_key() :: term()
  def checkpoint_key, do: @store_key

  @doc """
  Reads and derives the keypair, raising with a clear message on anything unusable.

  Public so that a deployment can rehearse its key configuration without booting a node,
  and so the refusal is testable directly. It reads a file and derives a public key; it
  registers nothing and returns a struct that redacts itself.
  """
  @spec load_key!(keyword()) :: Key.t()
  def load_key!(opts \\ []) when is_list(opts) do
    path = key_path!(opts)
    signer_id = signer_id!(opts)
    seed = read_seed!(path)
    warn_on_permissive_mode(path)

    {public, secret} = derive!(seed, path)
    %Key{signer_id: signer_id, public: public, secret: secret}
  end

  @impl true
  def init(opts) do
    # Raising here is the point: a `:signer` node whose key is missing, unreadable, or
    # malformed must not complete `Application.start/2`. `Ouroboros.Cluster.boot_role!/0`
    # refuses an unrecognized role the same way, and for the same reason — a host that
    # cannot do the one job its role names should fail loudly at boot rather than quietly
    # at the first request, when the failure looks like a deliberate denial.
    key = load_key!(opts)

    with {:ok, adapter, adapter_opts} <- storage(opts),
         {:ok, journal} <- load(adapter, adapter_opts) do
      {:ok,
       %{
         key: key,
         adapter: adapter,
         opts: adapter_opts,
         journal: journal,
         journal_limit: journal_limit(opts),
         policy: policy(opts),
         require_eval: require_eval(opts),
         rate_limit: rate_limit(opts),
         max_artifact_bytes: max_artifact_bytes(opts),
         window: %{},
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:sign, artifact, signer_id, request}, _from, state) do
    requester = requester(request)

    case admit(artifact, signer_id, request, requester, state) do
      {:ok, payload, findings, state} ->
        settle(:issued, payload, artifact, signer_id, requester, findings, state)

      {:refused, reason, state} ->
        settle(:refused, reason, artifact, signer_id, requester, %{}, state)
    end
  end

  def handle_call(:public_info, _from, state) do
    {:reply, {:ok, public_identity(state.key)}, state}
  end

  def handle_call(:decisions, _from, state) do
    {:reply, {:ok, Journal.public(state.journal)}, state}
  end

  def handle_call(:status, _from, state) do
    {:reply,
     {:ok,
      state.key
      |> public_identity()
      |> Map.merge(%{
        durability: state.durability,
        decisions: Journal.tally(state.journal),
        tracked_requesters: map_size(state.window),
        require_eval: state.require_eval,
        rate_limit_per_minute: state.rate_limit,
        policy: state.policy
      })}, state}
  end

  # ## Admission

  # Cheapest refusals first, then the rate limit, then the policy that has to read every
  # byte. The window is updated for every admitted request, refused or not: a flood of
  # refusals is still a flood.
  #
  # Everything after the rate limiter runs in `decide/5` rather than in this `with`,
  # because a `with/else` clause only ever sees the state this function was *called*
  # with. A policy refusal returning through `else` would silently discard the window
  # update, which would make refusals free — and a refusal is the one outcome a caller
  # can generate at will.
  defp admit(artifact, signer_id, request, requester, state) do
    with :ok <- validate_request(request, requester),
         :ok <- ensure_signer_id(signer_id, state),
         :ok <- ensure_size(artifact, state),
         {:ok, admitted} <- admit_rate(requester, state) do
      decide(artifact, signer_id, request, requester, admitted)
    else
      {:refused, reason} -> {:refused, reason, state}
      {:refused, reason, %{} = unchanged} -> {:refused, reason, unchanged}
    end
  end

  defp decide(artifact, signer_id, request, requester, state) do
    with {:ok, findings} <- evaluate(artifact, signer_id, requester, state),
         {:ok, payload} <- derive_payload(artifact, signer_id, request) do
      {:ok, payload, findings, state}
    else
      {:refused, reason} -> {:refused, reason, state}
    end
  end

  defp validate_request(request, requester) do
    cond do
      not is_map(request) -> {:refused, {:invalid_signing_request, describe(request)}}
      requester == :unknown -> {:refused, {:invalid_signing_request, :requester_required}}
      true -> validate_advisory_payload(Map.get(request, :payload))
    end
  end

  defp validate_advisory_payload(nil), do: :ok
  defp validate_advisory_payload(payload) when is_binary(payload), do: :ok

  defp validate_advisory_payload(payload),
    do: {:refused, {:invalid_signing_request, {:payload, describe(payload)}}}

  # The id in the envelope is the id an operator trusted a public key under. Signing a
  # request that names some other identity would produce a signature nobody can verify,
  # or worse, one that verifies under an identity this key was never meant to speak for.
  defp ensure_signer_id(signer_id, %{key: %Key{signer_id: signer_id}}), do: :ok

  defp ensure_signer_id(signer_id, _state),
    do: {:refused, {:unknown_signer_id, signer_id}}

  defp ensure_size(artifact, state) do
    bytes = byte_size(:erlang.term_to_binary(artifact))

    if bytes > state.max_artifact_bytes do
      {:refused, {:artifact_too_large, bytes, state.max_artifact_bytes}}
    else
      :ok
    end
  rescue
    error -> {:refused, {:invalid_artifact, Exception.message(error)}}
  end

  defp admit_rate(requester, state) do
    case Policy.rate_limit(state.window, requester, now_ms(), max: state.rate_limit) do
      {:ok, window} -> {:ok, %{state | window: window}}
      {:refused, reason} -> {:refused, reason, state}
    end
  end

  defp evaluate(artifact, signer_id, requester, state) do
    context = %{
      signer_id: signer_id,
      requester: requester,
      require_eval: state.require_eval,
      node: node()
    }

    case state.policy.evaluate(artifact, context) do
      {:ok, findings} when is_map(findings) -> {:ok, findings}
      {:ok, other} -> {:refused, {:invalid_policy_findings, describe(other)}}
      {:refused, reason} -> {:refused, reason}
      other -> {:refused, {:invalid_policy_result, describe(other)}}
    end
  rescue
    error -> {:refused, {:policy_exception, Exception.message(error)}}
  catch
    kind, reason -> {:refused, {:policy_failure, kind, inspect(reason)}}
  end

  # The bytes that get signed are derived here, from the artifact, every time. A caller's
  # payload is compared by digest and then discarded; it is never the thing signed.
  defp derive_payload(artifact, signer_id, request) do
    payload = Artifact.signing_payload(artifact, signer_id)

    case Map.get(request, :payload) do
      nil ->
        {:ok, payload}

      ^payload ->
        {:ok, payload}

      other ->
        {:refused, {:payload_mismatch, digest(payload), digest(other)}}
    end
  rescue
    error -> {:refused, {:invalid_artifact, Exception.message(error)}}
  end

  # ## Settlement

  # Checkpoint before reply, without exception. The signature is computed here so that a
  # crypto failure cannot leave the journal claiming an issuance that never happened, and
  # it is held until the journal write is acknowledged so a lost journal cannot leave a
  # signature that was never recorded. The one asymmetry that remains is deliberate: an
  # issued entry may describe a signature the requester never received, because the reply
  # travels after the write and can be lost. Over-recording is the safe direction.
  defp settle(:issued, payload, artifact, signer_id, requester, findings, state) do
    case sign(payload, state.key) do
      {:ok, signature} ->
        journal(:issued, nil, artifact, signer_id, requester, findings, state, {:ok, signature})

      {:refused, reason} ->
        settle(:refused, reason, artifact, signer_id, requester, findings, state)
    end
  end

  defp settle(:refused, reason, artifact, signer_id, requester, findings, state) do
    journal(:refused, reason, artifact, signer_id, requester, findings, state, {:refused, reason})
  end

  defp journal(decision, reason, artifact, signer_id, requester, findings, state, reply) do
    updated =
      Journal.record(
        state.journal,
        %{
          artifact_id: artifact_field(artifact, :id),
          epoch: artifact_field(artifact, :epoch),
          modules: artifact_modules(artifact),
          requester: requester,
          signer_id: signer_id,
          decision: decision,
          reason: reason,
          findings: findings
        },
        state.journal_limit
      )

    case checkpoint(updated, state) do
      :ok ->
        log(decision, reason, artifact, requester)
        {:reply, reply, %{state | journal: updated}}

      {:error, journal_reason} ->
        # A decision this signer could not record is a decision it will not report. The
        # policy reason is logged rather than returned, because the operative fact for
        # the requester is that the journal is unavailable, not what would have happened.
        Logger.error(
          "signing journal unavailable, refusing to sign: journal=#{inspect(journal_reason)} " <>
            "decision=#{inspect(decision)} reason=#{inspect(reason)} " <>
            "requester=#{inspect(requester)}"
        )

        {:reply, {:refused, {:journal_unavailable, journal_reason}}, state}
    end
  end

  defp log(:issued, _reason, artifact, requester) do
    Logger.info(
      "signing issued artifact=#{inspect(artifact_field(artifact, :id))} " <>
        "epoch=#{inspect(artifact_field(artifact, :epoch))} requester=#{inspect(requester)}"
    )
  end

  defp log(:refused, reason, artifact, requester) do
    Logger.warning(
      "signing refused artifact=#{inspect(artifact_field(artifact, :id))} " <>
        "requester=#{inspect(requester)} reason=#{inspect(reason)}"
    )
  end

  defp sign(payload, %Key{secret: secret}) do
    {:ok, :crypto.sign(:eddsa, :none, payload, [secret, :ed25519])}
  rescue
    # Deliberately not `Exception.message/1` on anything that saw the key: this reports
    # that signing failed and the exception's type, and nothing that touched the secret.
    error -> {:refused, {:signing_failed, error.__struct__}}
  catch
    kind, _reason -> {:refused, {:signing_failed, kind}}
  end

  # ## Journal storage

  defp checkpoint(journal, state) do
    case adapter_call(state.adapter, :put_checkpoint, [@store_key, journal, state.opts]) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_signing_storage_response, describe(other)}}
    end
  end

  # A journal this build cannot interpret stops the boot rather than being replaced. A
  # signer that has lost its record of what it signed must be looked at by a person
  # before it signs anything else.
  defp load(adapter, adapter_opts) do
    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
      :not_found ->
        {:ok, Journal.new()}

      {:ok, %Journal{} = journal} ->
        if Journal.valid?(journal),
          do: {:ok, journal},
          else: {:error, :invalid_signing_journal}

      {:ok, _other} ->
        {:error, :invalid_signing_journal}

      {:error, reason} ->
        {:error, {:signing_journal_unreadable, reason}}

      other ->
        {:error, {:invalid_signing_storage_response, describe(other)}}
    end
  end

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp storage(opts) do
    configured =
      Keyword.get_lazy(opts, :storage, fn ->
        Application.get_env(
          :ouroboros,
          :signing_journal_storage,
          {Jido.Storage.ETS, table: :ouroboros_signing_journal}
        )
      end)

    {adapter, adapter_opts} = Jido.Storage.normalize_storage(configured)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_signing_journal_storage, Exception.message(error)}}
  end

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  # ## Key loading

  defp key_path!(opts) do
    case Keyword.get_lazy(opts, :key_path, fn -> env(@key_path_env) end) do
      path when is_binary(path) and path != "" ->
        path

      _absent ->
        raise ArgumentError,
              "#{@key_path_env} must name a file holding this signer's Ed25519 seed. " <>
                "A :signer node refuses to boot without one, because a signer that " <>
                "cannot sign is indistinguishable from a signer that is denying."
    end
  end

  defp signer_id!(opts) do
    configured =
      Keyword.get_lazy(opts, :signer_id, fn ->
        case Application.get_env(:ouroboros, :signer_id) do
          id when is_binary(id) and id != "" -> id
          _absent -> env(@signer_id_env)
        end
      end)

    case configured do
      id when is_binary(id) and id != "" ->
        id

      _absent ->
        raise ArgumentError,
              "config :ouroboros, :signer_id (or #{@signer_id_env}) must name the identity " <>
                "this signer signs as. It is the id core nodes trust a public key under in " <>
                "OUROBOROS_UPGRADE_TRUSTED_SIGNERS, so it cannot be defaulted."
    end
  end

  # Nothing read out of this file reaches a message, a log line, or an exception. Sizes
  # and paths do; bytes never.
  defp read_seed!(path) do
    case File.read(path) do
      {:ok, contents} ->
        decode_seed!(contents, path)

      {:error, reason} ->
        raise ArgumentError,
              "#{@key_path_env} names #{inspect(path)}, which could not be read " <>
                "(#{inspect(reason)}). A :signer node refuses to boot without its key."
    end
  end

  defp decode_seed!(contents, _path) when byte_size(contents) == @seed_bytes, do: contents

  defp decode_seed!(contents, path) do
    trimmed = String.trim(contents)

    case Base.decode64(trimmed, padding: false) do
      {:ok, seed} when byte_size(seed) == @seed_bytes ->
        seed

      _other ->
        raise ArgumentError,
              "#{@key_path_env} names #{inspect(path)}, which does not hold an Ed25519 seed. " <>
                "Expected exactly #{@seed_bytes} raw bytes or their base64 encoding; the file " <>
                "holds #{byte_size(contents)} bytes."
    end
  end

  defp derive!(seed, path) do
    :crypto.generate_key(:eddsa, :ed25519, seed)
  rescue
    _error ->
      raise ArgumentError,
            "the seed in #{inspect(path)} is not a usable Ed25519 private key."
  end

  # A key file readable by more than its owner is a deployment mistake this runtime can
  # see and cannot fix. Refusing would be worse than saying so: on some filesystems the
  # mode is not meaningful, and a signer that will not boot because of an ACL is a signer
  # nobody runs.
  defp warn_on_permissive_mode(path) do
    case File.stat(path) do
      {:ok, %File.Stat{mode: mode}} ->
        if Bitwise.band(mode, 0o077) != 0 do
          Logger.warning(
            "signer key #{inspect(path)} is readable beyond its owner " <>
              "(mode #{Integer.to_string(Bitwise.band(mode, 0o777), 8)}); chmod 600 it"
          )
        end

      {:error, _reason} ->
        :ok
    end
  end

  defp public_identity(%Key{signer_id: signer_id, public: public}) do
    encoded = Base.encode64(public)

    %{
      node: node(),
      signer_id: signer_id,
      public_key: public,
      public_key_base64: encoded,
      trusted_signers_entry: "#{signer_id}:#{encoded}"
    }
  end

  # ## Options

  defp policy(opts) do
    case Keyword.get_lazy(opts, :policy, &Policy.configured/0) do
      module when is_atom(module) and not is_nil(module) -> module
      _invalid -> Policy.Default
    end
  end

  defp require_eval(opts) do
    Keyword.get_lazy(opts, :require_eval, fn ->
      Application.get_env(:ouroboros, :signing_require_eval, false)
    end) == true
  end

  defp rate_limit(opts) do
    positive(
      Keyword.get_lazy(opts, :rate_limit_per_minute, fn ->
        Application.get_env(:ouroboros, :signing_rate_limit_per_minute, @default_rate_limit)
      end),
      @default_rate_limit
    )
  end

  defp journal_limit(opts) do
    positive(
      Keyword.get_lazy(opts, :journal_limit, fn ->
        Application.get_env(:ouroboros, :signing_journal_limit, Journal.default_limit())
      end),
      Journal.default_limit()
    )
  end

  defp max_artifact_bytes(opts) do
    positive(
      Keyword.get_lazy(opts, :max_artifact_bytes, fn ->
        Application.get_env(
          :ouroboros,
          :signing_max_artifact_bytes,
          @default_max_artifact_bytes
        )
      end),
      @default_max_artifact_bytes
    )
  end

  defp positive(value, _default) when is_integer(value) and value > 0, do: value
  defp positive(_value, default), do: default

  # ## Plumbing

  defp call(server, message, fallback) do
    GenServer.call(server, message, @call_timeout)
  catch
    :exit, reason -> reason_tuple(fallback, reason)
  end

  defp reason_tuple({:refused, tag}, reason), do: {:refused, {tag, describe(reason)}}
  defp reason_tuple({:error, tag}, reason), do: {:error, {tag, describe(reason)}}

  defp requester(request) when is_map(request) do
    case Map.get(request, :requester) do
      requester when is_atom(requester) and not is_nil(requester) -> requester
      _other -> :unknown
    end
  end

  defp requester(_request), do: :unknown

  defp artifact_field(%Artifact{} = artifact, key), do: Map.get(artifact, key)
  defp artifact_field(_artifact, :id), do: ""
  defp artifact_field(_artifact, _key), do: nil

  defp artifact_modules(%Artifact{modules: modules}) when is_list(modules) do
    Enum.map(modules, fn
      %{module: module, disposition: disposition, sha256: sha256} ->
        %{module: module, disposition: disposition, sha256: sha256}

      other ->
        other
    end)
  end

  defp artifact_modules(_artifact), do: []

  defp digest(binary) when is_binary(binary),
    do: :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower)

  defp digest(other), do: describe(other)

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      value -> if String.trim(value) == "", do: nil, else: String.trim(value)
    end
  end

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
