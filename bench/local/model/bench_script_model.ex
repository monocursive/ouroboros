defmodule Ouroboros.Bench.ScriptModel do
  @moduledoc """
  A file-backed deterministic model for the local eval corpus. No network, no key, no spend.

  This is `Ouroboros.Test.NativeModelScript`'s idea moved across a process boundary.
  The test double encodes an `Agent` pid in the model spec, which works when the test and
  the loop share a BEAM. The corpus does not: `bench/local/run.exs` drives a *separate*
  daemon through `ouro run`, so the script has to be something both sides can name — a
  file.

  ## How a session reaches this module

  `Ouroboros.Provider.Native.Model.module/0` reads `config :ouroboros,
  :native_model_module`, which is node configuration and deliberately not a session
  option. The runner sets it on the daemon's command line rather than in a config file:

      ELIXIR_ERL_OPTIONS="-ouroboros native_model_module 'Elixir.Ouroboros.Bench.ScriptModel'"

  and points every session at a script directory through the ordinary model environment
  variable, `OUROBOROS_NATIVE_MODEL=bench-script:/abs/path/to/scripts`.

  The module itself is compiled into the project's own `ebin`, because Mix prunes the
  code path to the applications this project depends on: an `-pa` directory or an
  `ERL_LIBS` application is gone by the time `mix run --no-halt` boots. `run.exs` does
  that compile and says so; nothing here is expected to survive `mix clean`.

  ## How a request finds its script

  Two lookups, both derived from the request alone so that nothing has to be reset
  between tasks and two tasks may never interfere:

    * **Which script.** `index.json` lists `{instruction, script}` pairs, and a request
      matches the entry whose instruction the user message *contains*. Containment
      rather than equality because the runtime does not hand the model the prompt as
      typed: `Ouroboros.Provider.Native.Prompt` wraps it in an
      `<ouroboros-runtime version="1">` envelope, so the digest of the typed instruction
      matches nothing. `run.exs` refuses a corpus in which one instruction contains
      another, which is what makes "the longest match" unambiguous rather than lucky.
      Every user message is tried in order, so a rule injection or a steer that adds a
      message ahead of the prompt does not lose the script.
    * **Which response.** The Nth model call of a turn takes the Nth response, and N is
      the number of assistant messages already in the conversation. The loop appends
      exactly one assistant message per model call
      (`Ouroboros.Provider.Native.Loop`), so the count *is* the call index — no state,
      no counter, no cleanup.

  ## The script file

      {
        "instruction": "the exact prompt, for the index and for humans",
        "responses": [
          [
            {"type": "text", "text": "reading"},
            {"type": "tool_call", "id": "c1", "name": "read",
             "input": {"path": "lib/a.ex"}}
          ],
          [
            {"type": "text", "text": "done"},
            {"type": "usage", "input_tokens": 10, "output_tokens": 4},
            {"type": "finish", "reason": "stop"}
          ]
        ]
      }

  Chunk types are the normalized vocabulary of `Ouroboros.Provider.Native.Model`:
  `text`, `thinking`, `tool_call`, `usage`, `finish`.

  A script that cannot be found, parsed, or indexed is an `{:error, _}` rather than a
  plausible-looking answer: the loop turns that into a `turn_failed` and the task fails
  loudly, which is the only useful behaviour for a corpus whose whole job is to notice.
  """

  @behaviour Ouroboros.Provider.Native.Model

  @prefix "bench-script:"
  @index "index.json"

  # A script is small by construction. The cap is here so that a directory pointed at by
  # mistake cannot be read into the runtime's heap.
  @max_script_bytes 1_024 * 1_024

  @doc "The model spec that routes a session to a script directory."
  @spec model_spec(Path.t()) :: String.t()
  def model_spec(dir), do: @prefix <> dir

  @impl true
  def stream(request, _opts) do
    with {:ok, dir} <- script_dir(request.model),
         {:ok, index} <- read_json(Path.join(dir, @index)),
         {:ok, name} <- lookup(index, request.messages),
         {:ok, script} <- read_json(Path.join(dir, name)),
         {:ok, responses} <- responses(script, name) do
      {:ok, chunks(responses, call_index(request.messages))}
    end
  end

  @impl true
  def available?, do: true

  @impl true
  def credential_report,
    do: [%{provider: :bench_script, env: "OUROBOROS_NATIVE_MODEL", present: true}]

  # ----------------------------------------------------------------- resolution

  defp script_dir(@prefix <> dir) when byte_size(dir) > 0 do
    if File.dir?(dir), do: {:ok, dir}, else: {:error, {:bench_script_dir_missing, dir}}
  end

  defp script_dir(other), do: {:error, {:bench_script_spec_invalid, other}}

  defp lookup(%{"entries" => entries}, messages) when is_list(entries) do
    contents = user_contents(messages)

    contents
    |> Enum.find_value(fn content -> best_entry(entries, content) end)
    |> case do
      script when is_binary(script) -> {:ok, script}
      nil -> {:error, {:bench_script_unindexed, previews(contents)}}
    end
  end

  defp lookup(_malformed, _messages), do: {:error, {:bench_script_index_malformed, @index}}

  # The longest contained instruction wins. With `run.exs` refusing a corpus where one
  # instruction contains another, at most one can ever match — the sort is what makes
  # that a fact about the data rather than a hope about iteration order.
  defp best_entry(entries, content) do
    entries
    |> Enum.filter(fn
      %{"instruction" => i, "script" => s} when is_binary(i) and is_binary(s) ->
        i != "" and String.contains?(content, i)

      _other ->
        false
    end)
    |> Enum.max_by(&byte_size(&1["instruction"]), fn -> nil end)
    |> case do
      %{"script" => script} -> script
      nil -> nil
    end
  end

  # A miss cannot be debugged from a boolean. A bounded preview of what the model was
  # actually shown can be, and it is the difference between "the corpus is broken" and
  # "the prompt this runtime sends is not the one the task file declares".
  defp previews(contents), do: Enum.map(contents, &String.slice(&1, 0, 200))

  # The Nth model call of a turn takes the Nth response; see the moduledoc.
  defp call_index(messages), do: Enum.count(messages, &(role(&1) == :assistant))

  defp user_contents(messages) do
    messages
    |> Enum.filter(&(role(&1) == :user))
    |> Enum.map(&content/1)
    |> Enum.filter(&is_binary/1)
  end

  # The loop builds atom-keyed maps with atom roles. Both shapes are accepted anyway so
  # that a future wire form does not silently stop matching and start "exhausting".
  defp role(message) do
    case get(message, :role) do
      role when is_atom(role) -> role
      role when is_binary(role) -> String.to_existing_atom(role)
      _other -> nil
    end
  rescue
    ArgumentError -> nil
  end

  defp content(message), do: get(message, :content)

  defp get(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key))
    end
  end

  defp get(_other, _key), do: nil

  # ----------------------------------------------------------------- the script

  defp responses(%{"responses" => responses}, _name) when is_list(responses),
    do: {:ok, responses}

  defp responses(_other, name), do: {:error, {:bench_script_malformed, name}}

  defp chunks(responses, index) do
    case Enum.at(responses, index) do
      nil ->
        [{:text, "(bench script exhausted at call #{index})"}, {:finish, :stop}]

      chunks when is_list(chunks) ->
        Enum.flat_map(chunks, &chunk/1)

      _other ->
        [{:text, "(bench script response #{index} is not a list)"}, {:finish, :stop}]
    end
  end

  defp chunk(%{"type" => "text", "text" => text}) when is_binary(text), do: [{:text, text}]

  defp chunk(%{"type" => "thinking", "text" => text}) when is_binary(text),
    do: [{:thinking, text}]

  defp chunk(%{"type" => "tool_call", "id" => id, "name" => name} = call)
       when is_binary(id) and is_binary(name) do
    input = Map.get(call, "input", %{})
    [{:tool_call, %{id: id, name: name, input: if(is_map(input), do: input, else: %{})}}]
  end

  defp chunk(%{"type" => "usage"} = usage) do
    counts =
      usage
      |> Map.drop(["type"])
      |> Enum.flat_map(fn
        {key, value} when is_integer(value) -> [{String.to_atom(key), value}]
        _other -> []
      end)
      |> Map.new()

    [{:usage, counts}]
  end

  defp chunk(%{"type" => "finish"} = finish) do
    reason = Map.get(finish, "reason", "stop")
    [{:finish, if(is_binary(reason), do: String.to_atom(reason), else: :stop)}]
  end

  # An unknown chunk is dropped rather than guessed at. `run.exs` validates every script
  # against this vocabulary before a daemon is started, so reaching here means the
  # validator and this function disagree — and a silent guess would hide that.
  defp chunk(_unknown), do: []

  defp read_json(path) do
    with {:ok, %File.Stat{size: size}} when size <= @max_script_bytes <- File.stat(path),
         {:ok, body} <- File.read(path),
         {:ok, decoded} when is_map(decoded) <- JSON.decode(body) do
      {:ok, decoded}
    else
      {:ok, %File.Stat{size: size}} -> {:error, {:bench_script_too_large, path, size}}
      {:ok, _not_an_object} -> {:error, {:bench_script_malformed, path}}
      {:error, reason} -> {:error, {:bench_script_unreadable, path, reason}}
    end
  end
end
