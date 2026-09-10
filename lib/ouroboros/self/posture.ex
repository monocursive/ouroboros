defmodule Ouroboros.Self.Posture do
  @moduledoc """
  `OUROBOROS_POSTURE=self`, decided as a function rather than as a block in a config file
  (docs/SELF.md §2, S-D40).

  The posture is the one switch that lets a model session change the runtime it is running
  in: it shows the `forge` tool, names `Ouroboros.Wasm.PolicyEngine` as the permission
  engine, and turns on the boot that deploys what a previous installation forged. Every one
  of those is a widening, so the switch refuses the boot when any of its inputs is missing
  instead of falling back to a narrower thing that looks like it worked.

  ## Why this is a module and not fourteen lines of `config/runtime.exs`

  Because the refusals are the part worth testing, and a refusal written inside a config
  file can only be tested by booting a virtual machine per case. `configure/2` takes the
  environment as a map and this build's two relevant settings as a keyword list, and answers
  with the configuration to apply or with the sentence an operator reads. `config/runtime.exs`
  calls it and does exactly what it says.

  It stands on `String`, `Base`, `Map` and `File.regular?/1` alone — no application
  environment, no other module of this application, no process — for the reason
  `Ouroboros.DataDir` does: a config provider runs before this application's modules are
  guaranteed loadable, and a check that must be able to refuse a boot cannot depend on the
  supervision tree it is refusing to start.

  ## What it requires, and why each one

  | Variable | Why the posture cannot proceed without it |
  |---|---|
  | `OUROBOROS_NATIVE_MODEL` | The posture exists to let a model session forge. There is no session without a model. |
  | `OUROBOROS_SIGNING_NODE`, **or** `OUROBOROS_SIGNER_KEY_PATH` **and** `OUROBOROS_SIGNER_ID` | A lane-W signature comes from a `:signer` peer or from a service on this node (`Ouroboros.Wasm.Deploy` resolves them in that order). With neither, every forge ends at `:no_signing_service`. |
  | `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` | Development and test default to `allow_unsigned: true`. A posture that forges and deploys under that default would be deploying unsigned bytes, so the posture sets `allow_unsigned: false` and requires the list that makes anything deployable at all. |

  And two settings it does not set but will not run without: `wasm_forge_placement` must be
  `:local` and `signing_require_wasm_eval` must be `true`. Both are already the shipped
  defaults (`config/config.exs`, `upgrade/signing/service.ex`), so this is an assertion
  rather than a value — but a deployment that weakened either and then asked for this posture
  gets a refusal naming the setting rather than a quieter runtime.

  ## What it never does

  It does not read a key, mint a credential, relax a fence, or widen `policy_allowable_tools`.
  What a policy component has earned is `Ouroboros.Control.PolicyPromotion`'s record and is
  not reachable from an environment variable.
  """

  @posture_env "OUROBOROS_POSTURE"
  @model_env "OUROBOROS_NATIVE_MODEL"
  @signing_node_env "OUROBOROS_SIGNING_NODE"
  @key_path_env "OUROBOROS_SIGNER_KEY_PATH"
  @signer_id_env "OUROBOROS_SIGNER_ID"
  @trusted_signers_env "OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
  @self_ship_env "OUROBOROS_SELF_SHIP"

  @self "self"

  @type env :: %{optional(String.t()) => String.t() | nil}
  @type outcome :: :off | {:ok, keyword()} | {:error, String.t()}

  @doc "The variable that names a posture."
  @spec posture_env() :: String.t()
  def posture_env, do: @posture_env

  @doc "Every variable this posture reads, in the order the documentation introduces them."
  @spec variables() :: [String.t()]
  def variables,
    do: [
      @posture_env,
      @model_env,
      @signing_node_env,
      @key_path_env,
      @signer_id_env,
      @trusted_signers_env,
      @self_ship_env
    ]

  @doc """
  Reads the posture out of `env` and answers with what to configure.

  `:off` when `#{@posture_env}` is unset or empty — the default, and the only posture this
  build ships. `{:ok, keywords}` for `self`. `{:error, sentence}` for a missing input, an
  unusable one, a weakened `settings`, or any other posture name: an unrecognised posture is
  a refusal rather than a default, because the value an operator typed is the value they
  expected to be running under.

  `settings` carries this build's `:wasm_forge_placement` and `:signing_require_wasm_eval`,
  which the caller reads from application environment. They are arguments rather than reads
  so that this function stays pure and so a test can weaken one without touching the node.
  """
  @spec configure(env(), keyword()) :: outcome()
  def configure(env, settings \\ []) when is_map(env) and is_list(settings) do
    case value(env, @posture_env) do
      nil -> :off
      @self -> self_posture(env, settings)
      other -> {:error, unknown(other)}
    end
  end

  @doc """
  Parses `#{@trusted_signers_env}` into the `trusted_signers` map an
  `upgrade_trust_policy` carries, or a sentence naming what is wrong with it.

  `id:base64_ed25519_public_key`, comma separated, exactly the two lines
  `ouro wasm keygen` prints. Public because the export writes `signers.txt` in this format
  and a test that wrote its own parser would be proving the test.
  """
  @spec trusted_signers(String.t() | nil) ::
          {:ok, %{String.t() => binary()}} | {:error, String.t()}
  def trusted_signers(nil), do: {:ok, %{}}

  def trusted_signers(value) when is_binary(value) do
    value
    |> String.split(",", trim: true)
    |> Enum.reduce_while({:ok, %{}}, fn entry, {:ok, signers} ->
      case entry |> String.trim() |> String.split(":", parts: 2) do
        [id, encoded] ->
          case put_signer(signers, String.trim(id), String.trim(encoded)) do
            {:ok, signers} -> {:cont, {:ok, signers}}
            {:error, reason} -> {:halt, {:error, reason}}
          end

        _malformed ->
          {:halt, {:error, format()}}
      end
    end)
  end

  def trusted_signers(_other), do: {:error, format()}

  ## ── the `self` arm ────────────────────────────────────────────────────────────────────

  defp self_posture(env, settings) do
    with :ok <- required(env, @model_env, model_reason()),
         {:ok, signing} <- signing(env),
         {:ok, signers} <- signers(env),
         {:ok, ship?} <- ship(env),
         :ok <- unweakened(settings) do
      {:ok,
       [
         # S1. The tool a session forges through, off everywhere else.
         native_forge_tool: true,
         # S2. The engine that may consult a signed policy component for what the rules did
         # not decide, and the only engine a promotion record means anything to.
         permissions_engine: Ouroboros.Wasm.PolicyEngine,
         # Read by `Ouroboros.Self.Boot.enabled?/0` and by anything that wants to say what
         # posture this node is in without re-reading the environment.
         self_posture: true,
         self_ship: ship?,
         # Never `allow_unsigned` under this posture, in any environment. `config/config.exs`
         # allows unsigned artifacts outside production, which is a development convenience
         # this posture cannot have: it deploys what it forged.
         upgrade_trust_policy: [allow_unsigned: false, trusted_signers: signers]
       ] ++ signing}
    end
  end

  # Either a peer that holds the key or a key beside the application, and the two are not
  # the same posture: with `OUROBOROS_SIGNING_NODE` set this node forges and the peer signs
  # (`Ouroboros.Wasm.Deploy` prefers the configured node over any local service), and
  # `Ouroboros.Application` therefore starts no signing service here.
  defp signing(env) do
    node = value(env, @signing_node_env)
    key_path = value(env, @key_path_env)
    signer_id = value(env, @signer_id_env)

    cond do
      is_binary(node) ->
        {:ok, [signing_node: String.to_atom(node)] ++ signer_id(signer_id)}

      is_nil(key_path) and is_nil(signer_id) ->
        {:error, signer_reason()}

      is_nil(key_path) ->
        {:error,
         "#{@posture_env}=#{@self} names #{@signer_id_env} and no #{@key_path_env}. " <>
           "The identity without the key is a signer that cannot sign; " <> recipe()}

      is_nil(signer_id) ->
        {:error,
         "#{@posture_env}=#{@self} names #{@key_path_env} and no #{@signer_id_env}. " <>
           "The id is what core nodes trust a public key under in #{@trusted_signers_env}, " <>
           "so it cannot be defaulted; " <> recipe()}

      Path.type(key_path) != :absolute ->
        {:error,
         "#{@key_path_env}=#{key_path} must be an absolute path to this node's Ed25519 " <>
           "seed file. `ouro wasm keygen` prints an absolute one."}

      not File.regular?(key_path) ->
        {:error, "#{@key_path_env}=#{key_path} is not a readable file"}

      true ->
        {:ok, [signer_key_path: key_path, signer_id: signer_id]}
    end
  end

  # A `:signing_node` deployment may still name an id — it is what the remote signs as, and
  # `Ouroboros.Upgrade.Signing.Service` reads `config :ouroboros, :signer_id` before the
  # environment. Absent is fine there: the service is on the peer.
  defp signer_id(nil), do: []
  defp signer_id(id), do: [signer_id: id]

  defp signers(env) do
    case value(env, @trusted_signers_env) do
      nil ->
        {:error,
         "#{@posture_env}=#{@self} requires #{@trusted_signers_env}: this posture deploys " <>
           "what it forged, and a node that trusts nobody can deploy nothing. " <> recipe()}

      value ->
        case trusted_signers(value) do
          {:ok, signers} when map_size(signers) == 0 -> {:error, empty()}
          {:ok, signers} -> {:ok, signers}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  # On by default, because shipping what the previous installation forged is what the
  # posture is for. `false` is how an operator takes delivery of the posture without taking
  # delivery of `priv/self`, and an unusable value is a refusal rather than either default.
  defp ship(env) do
    case value(env, @self_ship_env) do
      nil -> {:ok, true}
      value when value in ["true", "1"] -> {:ok, true}
      value when value in ["false", "0"] -> {:ok, false}
      other -> {:error, "#{@self_ship_env} must be true or false, got: #{inspect(other)}"}
    end
  end

  defp unweakened(settings) do
    placement = Keyword.get(settings, :wasm_forge_placement, :local)
    require_eval = Keyword.get(settings, :signing_require_wasm_eval, true)

    cond do
      placement != :local ->
        {:error,
         "#{@posture_env}=#{@self} requires `config :ouroboros, :wasm_forge_placement` to be " <>
           ":local — the default — and this build has #{inspect(placement)}. The posture " <>
           "forges where the effect lands; a forwarded forge is a different deployment and " <>
           "not this one."}

      require_eval != true ->
        {:error,
         "#{@posture_env}=#{@self} requires `config :ouroboros, :signing_require_wasm_eval` " <>
           "to be true — the default — and this build has #{inspect(require_eval)}. Nothing " <>
           "here runs a component's own tests before the signature, so the signed " <>
           "evaluation spec is the whole test story for what a session forges."}

      true ->
        :ok
    end
  end

  ## ── reading and refusing ──────────────────────────────────────────────────────────────

  defp required(env, name, reason) do
    case value(env, name) do
      nil -> {:error, reason}
      _present -> :ok
    end
  end

  # An empty string is not a value. It is what an unset variable looks like in a shell
  # script that expanded something absent, and reading it as a setting is how a posture
  # boots half-configured.
  defp value(env, name) do
    case Map.get(env, name) do
      value when is_binary(value) ->
        case String.trim(value) do
          "" -> nil
          trimmed -> trimmed
        end

      _absent ->
        nil
    end
  end

  defp put_signer(_signers, "", _encoded), do: {:error, format()}
  defp put_signer(_signers, _id, ""), do: {:error, format()}

  defp put_signer(signers, id, encoded) do
    if Map.has_key?(signers, id) do
      {:error, "#{@trusted_signers_env} lists signer #{inspect(id)} more than once"}
    else
      case Base.decode64(encoded) do
        {:ok, key} when byte_size(key) == 32 ->
          {:ok, Map.put(signers, id, key)}

        _other ->
          {:error,
           "#{@trusted_signers_env} entry #{inspect(id)} must carry a base64-encoded " <>
             "32-byte Ed25519 public key"}
      end
    end
  end

  defp format,
    do:
      "#{@trusted_signers_env} must be comma-separated " <>
        "\"signer_id:base64_ed25519_public_key\" entries, exactly the line " <>
        "`ouro wasm keygen` prints"

  defp empty,
    do:
      "#{@trusted_signers_env} is set and lists nobody. " <>
        "A node that trusts no signer can deploy nothing. " <> recipe()

  defp model_reason,
    do:
      "#{@posture_env}=#{@self} requires #{@model_env}: the posture exists so a model " <>
        "session can forge, and there is no session without a model."

  defp signer_reason,
    do:
      "#{@posture_env}=#{@self} requires a signer. Set #{@signing_node_env} to a " <>
        "`:signer`-role peer, or #{@key_path_env} and #{@signer_id_env} to run the " <>
        "one-machine posture with the key beside the application. " <> recipe()

  defp unknown(other),
    do:
      "#{@posture_env} must be #{inspect(@self)} or unset, got: #{inspect(other)}. " <>
        "An unrecognised posture is refused rather than ignored: a node running a posture " <>
        "nobody named is a node whose fences nobody chose."

  defp recipe,
    do:
      "`ouro wasm keygen --id <name>` prints the three lines this posture needs " <>
        "(docs/SELF.md §2)."
end
