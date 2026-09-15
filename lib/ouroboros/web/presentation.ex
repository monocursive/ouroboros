defmodule Ouroboros.Web.Presentation do
  @moduledoc """
  The one place an internal name becomes a word a reader was meant to see.

  Two things reach this surface that were never addressed to a person: the BEAM's node
  names and the runtime's own refusal terms — bare atoms, `{:error, reason}` pairs, and
  the numeric JSON-RPC codes the gateway answers with. `docs/design-qa/ui-review-2026-09-15.md`
  §3.5 found all three on screen: `nonode@nohost` on `/status` and `/settings`, and
  `Audit operation failed: :audit_disabled` as the first line of `/audit`.

  The parity plan's sixth ground rule is that neither ever reaches a template raw, and
  that each surface has **one** function per kind rather than a phrase invented at each
  call site. These are the web's two. The TUI's are `ui::presentation` (T2.8).

  ## What this may not do

  Translate, never invent. `node_label/2` shortens and names; it does not decide that a
  machine is reachable, and it does not borrow a label from a roster that does not carry
  one. `refusal/1` rewrites the runtime's own word into a sentence about the same
  condition; where it has no sentence for a term it says the term in words rather than
  guessing at a cause. Nothing here claims what the runtime did not report.
  """

  @this_computer "this computer"

  # The node name a BEAM that was never given one answers with. It is not a machine name;
  # it is the absence of one, and the honest reading of it is "the computer you are
  # already talking to".
  @unnamed "nonode@nohost"

  # Terms this surface has a sentence for. Everything else is turned into words rather
  # than given a meaning nobody wrote down — see `sentence_for/2`.
  @sentences %{
    "audit_disabled" =>
      "Audit recording is disabled on this runtime; there is nothing recorded to search.",
    "audit_unavailable" => "The audit store on this runtime could not be opened.",
    "not_found" => "The runtime has no record of that.",
    "unavailable" => "That part of the runtime is not available here.",
    "timeout" => "The runtime did not answer in time."
  }

  # The gateway's own numeric vocabulary (`Ouroboros.Gateway.Methods.codes/0`), as
  # sentences. A code is a thing two programs say to each other; it is never the answer to
  # a person's question.
  @codes %{
    -32700 => "The runtime could not read that request.",
    -32600 => "The runtime refused that request.",
    -32601 => "This runtime does not serve that request.",
    -32602 => "The runtime refused this request's parameters.",
    -32001 => "This surface is not authenticated to the runtime.",
    -32002 => "This surface and the runtime speak different protocol versions.",
    -32003 => "This endpoint's scope does not allow that.",
    -32004 => "That part of the runtime is not available here.",
    -32005 => "The runtime stopped answering before it finished.",
    -32006 => "The runtime reported a failure from further upstream.",
    -32007 => "The runtime has no record of that."
  }

  @doc "The label for a machine nobody named — the string every caller may compare against."
  @spec this_computer() :: String.t()
  def this_computer, do: @this_computer

  @doc """
  What to call the machine a node name points at.

  `nil`, `""`, `:nonode@nohost` and `"nonode@nohost"` are all the same fact — a runtime
  that was never given a name — and they read as "#{@this_computer}". A real
  `name@host` reads as its `name`, which is the half an operator chose; the host half is
  the BEAM's addressing and belongs in `/status`, not in a session's vitals.

  `machines` is an optional roster in `runtime.status`'s own shape
  (`cluster.fleet.machines`, each `%{node: …, machine: …}`). Where one of its entries
  names this node, **its** label wins: a fleet that has been told what a machine is called
  knows better than a string split does.
  """
  @spec node_label(term(), [map()]) :: String.t()
  def node_label(node, machines \\ [])

  def node_label(nil, _machines), do: @this_computer

  def node_label(node, machines) when is_binary(node) do
    case String.trim(node) do
      "" -> @this_computer
      @unnamed -> @this_computer
      name -> fleet_label(name, machines) || name |> String.split("@", parts: 2) |> hd()
    end
  end

  def node_label(node, machines) when is_atom(node),
    do: node |> Atom.to_string() |> node_label(machines)

  def node_label(node, machines) when is_number(node) or is_list(node),
    do: node |> to_string() |> node_label(machines)

  # Absent is "this computer" because absent is what an unnamed BEAM answers with.
  # *Unreadable* is a different fact and gets a different word: something was reported and
  # this surface could not read it, which is not the same as nothing having been reported.
  def node_label(_unreadable, _machines), do: "not reported"

  # Only a label the roster actually carries, and only one that is not the node name it
  # was derived from — an entry that merely repeats the node teaches nothing.
  defp fleet_label(name, machines) when is_list(machines) do
    Enum.find_value(machines, fn machine ->
      with true <- is_map(machine),
           node when not is_nil(node) <- Map.get(machine, :node) || Map.get(machine, "node"),
           true <- to_string(node) == name,
           label when is_binary(label) <-
             Map.get(machine, :machine) || Map.get(machine, "machine"),
           trimmed when trimmed != "" and trimmed != name <- String.trim(label) do
        trimmed
      else
        _no_label -> nil
      end
    end)
  end

  defp fleet_label(_name, _machines), do: nil

  @doc """
  One refusal, as a sentence.

  Takes whatever the runtime handed back — a bare atom, `{:error, reason}`, the gateway's
  `{:error, code, message}` and `{:error, code, message, data}`, a `%{code:, message:}`
  map, or a message string that has an inspected atom or a numeric code embedded in it —
  and answers a sentence about the same condition. `nil` in, `nil` out, so a template can
  keep drawing a refusal only when there is one.

  A term this module has no sentence for is spelled in words rather than dropped: the
  operator still needs to be able to name what happened when they ask about it, and a
  swallowed refusal is worse than an awkward one.
  """
  @spec refusal(term()) :: String.t() | nil
  def refusal(nil), do: nil
  def refusal({:error, reason}), do: refusal(reason)

  def refusal({:error, code, message}) when is_integer(code),
    do: from_code(code, message)

  def refusal({:error, code, message, _data}) when is_integer(code),
    do: from_code(code, message)

  def refusal(%{} = refused) do
    code = Map.get(refused, :code) || Map.get(refused, "code")
    message = Map.get(refused, :message) || Map.get(refused, "message")

    cond do
      is_integer(code) -> from_code(code, message)
      is_binary(message) -> refusal(message)
      true -> "The runtime refused this and did not say what it was."
    end
  end

  def refusal(message) when is_binary(message), do: rewrite(message)

  def refusal(reason) when is_atom(reason),
    do: reason |> Atom.to_string() |> sentence_for("")

  def refusal(other), do: other |> inspect(limit: 3) |> rewrite()

  # A message the runtime wrote is preferred over this module's word for the code: it is
  # the more specific of the two. The code is the fallback, never a suffix — a number in
  # brackets is the exact thing §3.5 asked to stop drawing.
  defp from_code(code, message) when is_binary(message) do
    case String.trim(message) do
      "" -> Map.get(@codes, code, generic())
      _stated -> rewrite(message)
    end
  end

  defp from_code(code, _message), do: Map.get(@codes, code, generic())

  defp generic, do: "The runtime refused this and did not say why."

  # `inspect/1` is how an atom reaches a message in the first place
  # (`gateway/methods.ex:611`), so an inspected atom at the end of one is read back off
  # and answered as the condition it names.
  defp rewrite(message) do
    trimmed = String.trim(message)

    case Regex.run(~r/\A(.*?)[:\s-]*:([a-z][a-zA-Z0-9_]*)\z/s, trimmed, capture: :all_but_first) do
      [prefix, term] -> sentence_for(term, prefix)
      nil -> without_codes(trimmed)
    end
  end

  defp sentence_for(term, prefix) do
    case Map.fetch(@sentences, term) do
      {:ok, sentence} ->
        sentence

      :error ->
        words = String.replace(term, "_", " ")

        case String.trim(prefix) do
          "" -> String.capitalize(words) <> "."
          stated -> "#{stated}: #{words}."
        end
    end
  end

  # A message that carries a raw code, with the code taken out. The sentence the code
  # stands for is already this module's answer when there is no message at all; repeating
  # it here would say the same thing twice.
  defp without_codes(message) do
    message
    |> String.replace(~r/\s*[(\[]?-32\d{3}[)\]]?/, "")
    |> String.trim()
    |> case do
      "" -> generic()
      cleaned -> cleaned
    end
  end
end
