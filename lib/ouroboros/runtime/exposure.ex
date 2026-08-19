defmodule Ouroboros.Runtime.Exposure do
  @moduledoc """
  The model-facing view of this runtime: identity plus a compact live snapshot.

  `Ouroboros.status/0` is the operator tree. This module is the slice a selected
  model is allowed to see — signer posture, live capabilities, mesh members, and
  the proposal root — rendered inside `<ouroboros-runtime>` so it cannot be
  confused with user text. It never carries tokens, system prompts, or grants.

  Admission captures the complete rendered envelope for durable task/session
  state. Dispatch then reuses those exact bytes, so retries and recovery cannot
  silently observe a different runtime. Durable user text is not rewritten; a
  prompt that forges this block's delimiters is refused rather than escaped.
  """

  alias Ouroboros.AgentProfile
  alias Ouroboros.Cluster
  alias Ouroboros.Mesh
  alias Ouroboros.Runtime.Manifesto
  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Upgrade.Rollout.Registry

  @open "<ouroboros-runtime"
  @close "</ouroboros-runtime>"
  @capture_version 1
  @max_agents 32
  @max_live 32

  @doc "The opening delimiter this envelope uses."
  @spec open_tag() :: String.t()
  def open_tag, do: @open

  @doc "Operator-facing forge posture, shared with `Ouroboros.status/0`."
  @spec forge_status() :: map()
  def forge_status do
    live = live_capabilities()

    %{
      signer: signer_kind(),
      admit_possible?: admit_possible?(),
      live_count: length(live),
      live: live
    }
  end

  @doc "The compact snapshot rendered into the model envelope."
  @spec snapshot() :: map()
  def snapshot do
    forge = forge_status()

    %{
      node: node(),
      role: Cluster.role(),
      signer: forge.signer,
      admit_possible?: forge.admit_possible?,
      live: forge.live,
      agents: mesh_agents(),
      proposal_root: Manifesto.proposal_root()
    }
  end

  @doc """
  Renders the `<ouroboros-runtime>` envelope.

  Pass `:static` for identity only (no live facts). Pass a snapshot map to pin
  facts. With no argument, a fresh snapshot is taken.
  """
  @spec envelope() :: String.t()
  def envelope, do: envelope(snapshot())

  @spec envelope(:static | map()) :: String.t()
  def envelope(:static), do: envelope(%{})
  def envelope(snapshot) when is_map(snapshot), do: render(snapshot)

  @doc "Captures the exact model-facing runtime envelope for durable reuse."
  @spec capture(keyword() | map()) :: map()
  def capture(extras \\ [])

  def capture(extras) when is_list(extras) or is_map(extras) do
    envelope = extras |> live_snapshot() |> envelope()

    %{
      version: @capture_version,
      envelope: envelope,
      digest: digest(envelope)
    }
  end

  @doc "Returns whether a durable capture is intact and safe to reuse."
  @spec valid_capture?(term()) :: boolean()
  def valid_capture?(%{version: @capture_version, envelope: envelope, digest: expected})
      when is_binary(envelope) and is_binary(expected) do
    String.valid?(envelope) and valid_envelope?(envelope) and
      secure_equal?(digest(envelope), expected)
  end

  def valid_capture?(_capture), do: false

  @doc "Prefixes user text with a live envelope, refusing reserved delimiters."
  @spec wrap_prompt(term()) :: {:ok, String.t()} | {:error, term()}
  def wrap_prompt(text), do: wrap_prompt(text, [])

  @spec wrap_prompt(term(), keyword() | map()) :: {:ok, String.t()} | {:error, term()}
  def wrap_prompt(text, extras) when is_binary(text) and (is_list(extras) or is_map(extras)) do
    wrap_prompt_capture(text, capture(extras))
  end

  def wrap_prompt(_text, _extras), do: {:error, :invalid_prompt}

  @doc "Prefixes user text with an admission-time capture, refusing invalid captures and delimiters."
  @spec wrap_prompt_capture(term(), term()) :: {:ok, String.t()} | {:error, term()}
  def wrap_prompt_capture(text, capture) when is_binary(text) do
    cond do
      not String.valid?(text) ->
        {:error, :invalid_prompt}

      AgentProfile.reserved_delimiter?(text) ->
        {:error, {:reserved_prompt_delimiter, :prompt}}

      not valid_capture?(capture) ->
        {:error, :invalid_runtime_capture}

      true ->
        {:ok, capture.envelope <> "\n\n" <> text}
    end
  end

  def wrap_prompt_capture(_text, _capture), do: {:error, :invalid_prompt}

  @doc "Wraps a Harness turn request's prompt field, leaving every other field alone."
  @spec wrap_turn_request(map() | struct()) :: {:ok, map() | struct()} | {:error, term()}
  def wrap_turn_request(request), do: wrap_turn_request(request, [])

  @spec wrap_turn_request(map() | struct(), keyword() | map()) ::
          {:ok, map() | struct()} | {:error, term()}
  def wrap_turn_request(%{prompt: prompt} = request, extras)
      when is_binary(prompt) and (is_list(extras) or is_map(extras)) do
    case wrap_prompt(prompt, extras) do
      {:ok, wrapped} -> {:ok, %{request | prompt: wrapped}}
      error -> error
    end
  end

  def wrap_turn_request(request, _extras), do: {:ok, request}

  @doc "Wraps a turn request with a previously captured runtime envelope."
  @spec wrap_turn_request_capture(map() | struct(), term()) ::
          {:ok, map() | struct()} | {:error, term()}
  def wrap_turn_request_capture(%{prompt: prompt} = request, capture) when is_binary(prompt) do
    case wrap_prompt_capture(prompt, capture) do
      {:ok, wrapped} -> {:ok, %{request | prompt: wrapped}}
      error -> error
    end
  end

  def wrap_turn_request_capture(request, _capture), do: {:ok, request}

  defp render(snapshot) do
    body =
      ["## Host", Manifesto.body(), format_live(snapshot)]
      |> Enum.reject(&(&1 in [nil, ""]))
      |> Enum.join("\n\n")

    @open <>
      " version=\"#{Manifesto.version()}\">\n" <>
      body <>
      "\n" <> @close
  end

  defp format_live(snapshot) when snapshot == %{}, do: nil

  defp format_live(snapshot) do
    live = List.wrap(Map.get(snapshot, :live, []))
    agents = List.wrap(Map.get(snapshot, :agents, []))

    lines =
      [
        "## Live",
        "node: #{format_node(Map.get(snapshot, :node))}",
        "role: #{Map.get(snapshot, :role, :unknown)}",
        "signer: #{Map.get(snapshot, :signer, :unknown)}",
        "admit_possible: #{Map.get(snapshot, :admit_possible?, false)}"
      ] ++
        sandbox_lines(snapshot) ++
        [
          "proposal_root: #{Map.get(snapshot, :proposal_root, Manifesto.proposal_root())}",
          "live_capabilities:"
        ]

    live_lines =
      case live do
        [] -> ["  (none)"]
        entries -> Enum.map(entries, &("  - " <> format_live_entry(&1)))
      end

    agent_header = ["mesh_agents:"]

    agent_lines =
      case agents do
        [] -> ["  (none)"]
        entries -> Enum.map(entries, &("  - " <> format_agent(&1)))
      end

    Enum.join(lines ++ live_lines ++ agent_header ++ agent_lines, "\n")
  end

  defp live_snapshot(extras) do
    snapshot = snapshot()

    if extras_has_sandbox?(extras) do
      Map.put(snapshot, :sandbox, sandbox_from(extras))
    else
      snapshot
    end
  end

  defp extras_has_sandbox?(extras) when is_list(extras),
    do: Keyword.has_key?(extras, :sandbox_mode) or Keyword.has_key?(extras, :sandbox)

  defp extras_has_sandbox?(extras) when is_map(extras),
    do:
      Map.has_key?(extras, :sandbox_mode) or Map.has_key?(extras, :sandbox) or
        Map.has_key?(extras, "sandbox_mode")

  defp sandbox_from(extras) when is_list(extras),
    do: Keyword.get(extras, :sandbox_mode, Keyword.get(extras, :sandbox))

  defp sandbox_from(extras) when is_map(extras),
    do:
      Map.get(extras, :sandbox_mode) || Map.get(extras, :sandbox) ||
        Map.get(extras, "sandbox_mode")

  defp sandbox_lines(snapshot) do
    case Map.fetch(snapshot, :sandbox) do
      :error -> []
      {:ok, sandbox} -> ["sandbox: #{format_sandbox(sandbox)}"]
    end
  end

  defp format_sandbox(nil), do: "unset"
  defp format_sandbox(value) when is_atom(value), do: Atom.to_string(value)
  defp format_sandbox(value) when is_binary(value), do: value
  defp format_sandbox(other), do: inspect(other, limit: 8)

  defp format_node(nil), do: "unknown"
  defp format_node(node), do: to_string(node)

  defp format_live_entry(%{module: module, epoch: epoch, state: state}),
    do: "#{module} epoch=#{epoch} #{state}"

  defp format_live_entry(other), do: inspect(other, limit: 8)

  defp format_agent(%{id: id, module: module, role: role}) do
    [id, module, role]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  defp format_agent(other), do: inspect(other, limit: 8)

  defp signer_kind do
    case Signer.configured() do
      {Signer.Deny, _opts} -> :deny
      {Signer.Local, _opts} -> :local
      {Signer.Remote, _opts} -> :remote
      {_other, _opts} -> :other
    end
  end

  defp admit_possible?, do: signer_kind() != :deny

  defp live_capabilities do
    Registry.live()
    |> Enum.take(@max_live)
    |> Enum.map(fn entry ->
      %{
        module: inspect(entry.module),
        epoch: entry.epoch,
        state: entry.state
      }
    end)
  catch
    :exit, _reason -> []
    _kind, _reason -> []
  end

  defp mesh_agents do
    Mesh.list_agents()
    |> Enum.take(@max_agents)
    |> Enum.map(&project_agent/1)
  catch
    :exit, _reason -> []
    _kind, _reason -> []
  end

  defp project_agent(%{id: id}) do
    case Mesh.state(id) do
      {:ok, %{agent_module: module, agent: %{state: state}}} when is_map(state) ->
        %{id: id, module: inspect(module), role: Map.get(state, :role)}

      {:ok, %{agent_module: module}} ->
        %{id: id, module: inspect(module), role: nil}

      _other ->
        %{id: id, module: nil, role: nil}
    end
  catch
    _kind, _reason -> %{id: id, module: nil, role: nil}
  end

  defp valid_envelope?(envelope) do
    case String.split(envelope, "\n", parts: 2) do
      [opening, body] ->
        Regex.match?(~r/\A<ouroboros-runtime version="[1-9][0-9]*">\z/, opening) and
          String.ends_with?(body, "\n" <> @close) and
          not String.contains?(body, @open) and
          body |> String.trim_trailing(@close) |> String.contains?(@close) |> Kernel.not()

      _other ->
        false
    end
  end

  defp digest(text) do
    :sha256
    |> :crypto.hash(text)
    |> Base.encode16(case: :lower)
  end

  defp secure_equal?(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
       do: :crypto.hash_equals(left, right)

  defp secure_equal?(_left, _right), do: false
end
