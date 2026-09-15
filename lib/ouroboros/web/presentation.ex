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
    "audit_disabled" => "Audit recording is disabled on this runtime.",
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
  that was never given a name — and they read as "#{@this_computer}".

  A real `release@host` reads as its **host**. The half before the `@` is the release
  name, which every machine in a fleet shares: `ouro@alpha` and `ouro@beta` are two
  machines, and shortening both to "ouro" would put the same word under two presence dots
  and leave a reader unable to tell which one went dark. The host is the half that differs.

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
      name -> fleet_label(name, machines) || host_of(name)
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

  # The half after the `@`, where there is one and it says something. `"alpha"` with no
  # host at all is already the machine; `"@build-box"` is a host with no release and reads
  # as the host rather than as the empty string in front of it.
  defp host_of(name) do
    case String.split(name, "@", parts: 2) do
      [release, ""] -> release
      [_release, host] -> host
      [release] -> release
    end
  end

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
  map, or a message string with an inspected term or a numeric code embedded in it — and
  answers a sentence about the same condition. `nil` in, `nil` out, so a template can keep
  drawing a refusal only when there is one.

  ## What it may not do to a message

  Rewrite it. Everything the runtime wrote for a person is kept: the only things taken
  out are an inspected Elixir term, which was never addressed to anybody, and a protocol
  code in brackets or at the very end of the line. A `-32xxx`-shaped run of digits inside
  a path or a token count is part of the message and stays there.

  The half of a message *before* an inspected term is kept too. `read scope may not run
  interactive.answer: :unavailable` names the verb that was refused, and that half is the
  operator's whole question; the sentence is appended to it rather than put in its place.

  A term this module has no sentence for is spelled in words rather than dropped: the
  operator still needs to be able to name what happened, and a swallowed refusal is worse
  than an awkward one. Nothing here guesses at a cause.
  """
  @spec refusal(term()) :: String.t() | nil
  def refusal(nil), do: nil

  # `:ok` is not a refusal, and dressing it as one ("Ok.") would be this module inventing
  # a failure. A caller that reaches here with a success has nothing to draw.
  def refusal(:ok), do: nil

  def refusal({:error, reason}), do: refusal(reason)

  def refusal({:error, code, message}), do: from_code(code, message, nil)
  def refusal({:error, code, message, data}), do: from_code(code, message, data)

  def refusal(%{} = refused) do
    code = Map.get(refused, :code) || Map.get(refused, "code")
    message = Map.get(refused, :message) || Map.get(refused, "message")
    data = Map.get(refused, :data) || Map.get(refused, "data")

    case {numeric(code), message} do
      {nil, message} when is_binary(message) -> with_outcome(rewrite(message), data)
      {nil, nil} -> "The runtime refused this and did not say what it was."
      {nil, other} -> refusal(other)
      {code, message} -> from_code(code, message, data)
    end
  end

  def refusal(message) when is_binary(message), do: rewrite(message)

  def refusal(reason) when is_atom(reason), do: sentence_for(Atom.to_string(reason), "")

  # A reason that is not an atom, a string or one of the gateway's tuples. `inspect/1` is
  # what `gateway/methods.ex:611` would have done with it; this says the same parts in
  # words instead, and claims nothing about why.
  def refusal(other) when is_tuple(other) or is_list(other) do
    case term_words(other) do
      "" -> generic()
      words -> "The runtime reported: " <> words <> "."
    end
  end

  def refusal(other), do: "The runtime reported: " <> term_words(other) <> "."

  # A message the runtime wrote is preferred over this module's word for the code: it is
  # the more specific of the two. The code is the fallback, never a suffix — a number in
  # brackets is the exact thing §3.5 asked to stop drawing.
  defp from_code(code, message, data) do
    code = numeric(code)

    sentence =
      case message do
        message when is_binary(message) ->
          case String.trim(message) do
            "" -> Map.get(@codes, code, generic())
            _stated -> rewrite(message)
          end

        _unstated ->
          Map.get(@codes, code, generic())
      end

    with_outcome(sentence, data)
  end

  # `Ouroboros.Web.Call` marks the methods for which "did not happen" and "happened and
  # was not reported" are different answers, and says in its own moduledoc that the
  # difference is the operator's whole question. Dropping the marker here would throw that
  # away at the last step.
  defp with_outcome(sentence, %{"outcome" => "unknown"}),
    do: sentence <> " Whether it happened anyway is not something this runtime reported."

  defp with_outcome(sentence, _data), do: sentence

  defp numeric(code) when is_integer(code), do: code

  defp numeric(code) when is_binary(code) do
    case Integer.parse(String.trim(code)) do
      {code, ""} -> code
      _not_a_code -> nil
    end
  end

  defp numeric(_code), do: nil

  defp generic, do: "The runtime refused this and did not say why."

  # `inspect/1` is how a term reaches a message in the first place
  # (`gateway/methods.ex:611`), so an inspected term at the end of one is read back off and
  # said in words. The half in front of it is the runtime's own sentence and is kept.
  defp rewrite(message) do
    trimmed = String.trim(message)

    cond do
      match =
          Regex.run(~r/\A(.*?)[:\s-]*:([a-z][a-zA-Z0-9_]*)\z/s, trimmed, capture: :all_but_first) ->
        [prefix, term] = match
        sentence_for(term, prefix)

      match =
          Regex.run(~r/\A(.*?)[:\s-]*([{\[].*[}\]])\z/s, trimmed, capture: :all_but_first) ->
        [prefix, term] = match
        joined(String.trim(prefix), tidy_term(term))

      true ->
        without_codes(trimmed)
    end
  end

  defp sentence_for(term, prefix) do
    prefix = String.trim(prefix)
    words = String.replace(term, "_", " ")

    case Map.fetch(@sentences, term) do
      {:ok, sentence} ->
        joined(prefix, sentence)

      :error ->
        # `Audit operation failed: :audit_operation_failed` is one condition said twice;
        # the prefix already is the sentence.
        if String.downcase(prefix) == words,
          do: ending(prefix),
          else: joined(prefix, ending(String.capitalize(words)))
    end
  end

  defp joined("", sentence), do: ending(sentence)
  defp joined(prefix, sentence), do: ending(prefix <> ": " <> sentence)

  defp ending(""), do: generic()

  defp ending(sentence) do
    if String.ends_with?(sentence, [".", "!", "?"]), do: sentence, else: sentence <> "."
  end

  # An inspected term, as its parts rather than as Elixir. Nothing is evaluated: the
  # punctuation `inspect/1` added is taken back off and what is left is the words the
  # runtime put in.
  defp tidy_term(text) do
    text
    |> String.replace(~r/[{}\[\]"]/, "")
    |> String.split(",")
    |> Enum.map(&tidy_part/1)
    |> Enum.reject(&(&1 in ["", "error", "nil"]))
    |> Enum.join(", ")
  end

  defp tidy_part(part) do
    part = part |> String.trim() |> String.trim_leading(":")

    if part =~ ~r/\A[a-z][a-zA-Z0-9_]*\z/,
      do: String.replace(part, "_", " "),
      else: part
  end

  defp term_words(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> term_words()

  defp term_words(terms) when is_list(terms) do
    terms
    |> Enum.map(&term_words/1)
    |> Enum.reject(&(&1 in ["", "error", "nil"]))
    |> Enum.join(", ")
  end

  defp term_words(nil), do: "nil"
  defp term_words(term) when is_atom(term), do: String.replace(Atom.to_string(term), "_", " ")
  defp term_words(term) when is_binary(term), do: term
  defp term_words(term) when is_number(term), do: to_string(term)
  defp term_words(term), do: inspect(term, limit: 3)

  # A protocol code the message carried, taken out only where it is punctuation rather
  # than content: in brackets, or at the very end of the line. A `-32xxx`-shaped run of
  # digits inside a path (`/var/log/ouro-32001/boot`) or a token count is part of what the
  # runtime said and is left exactly where it is.
  defp without_codes(message) do
    message
    |> String.replace(~r/\s*[(\[]-32\d{3}[)\]]/, "")
    |> String.replace(~r/[\s:,-]+-32\d{3}\.?\z/, "")
    |> String.trim()
    |> case do
      "" -> generic()
      cleaned -> cleaned
    end
  end
end
