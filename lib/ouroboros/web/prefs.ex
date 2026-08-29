defmodule Ouroboros.Web.Prefs do
  @moduledoc """
  The new-session form's defaults, kept in `<data_dir>/web.prefs.json`.

  ## Why this is a server-side file and not `localStorage`

  `config.toml`'s `[defaults]` block belongs to the *terminal client's* machine — it is
  read before there is a runtime, on the host the operator typed `ouro` on. The browser has
  no such file, and the daemon it is driving may be on a different machine entirely, so
  `docs/WEB.md` §4 (D10) gives the web surface its own home in the data directory. The
  split it draws is the one this module implements: things that describe *the work* —
  which provider, which model, which workspace, what sandbox, how much thinking — are
  facts about this runtime and belong beside it; per-browser conveniences (the theme, a
  collapsed section) stay in `localStorage`, where a second operator's tab cannot inherit
  them.

  ## What gets written, and when

  Exactly the keys the operator **stated** on a start that actually succeeded. The map
  handed to `write/2` is `Ouroboros.Web.Live.NewSession.start_params/2`'s own answer minus
  its `id`, so a control the operator never touched writes nothing and cannot become a
  default by being drawn. A refused start writes nothing at all: a request the plane
  rejected is not evidence about how the operator likes to work.

  ## What reading it can do to a page: nothing

  `read/1` is **total**. Absent, unreadable, oversized, not a regular file, not JSON, JSON
  that is not an object, an object holding numbers where strings belong, a `sandbox_mode`
  no adapter has ever heard of — every one of them answers `%{}` or drops the offending
  key, and the corrupt cases say so once in the log. A preferences file has no business
  being able to take the new-session form down, and the failure mode of "no defaults" is a
  form that behaves exactly as it did before this file existed.

  Values are validated against the same vocabularies the form sends by, rather than trusted
  and passed along: a stale `sandbox_mode` would otherwise seed a control that cannot draw
  it and then travel to a plane that would refuse it with a `-32602` naming the parameter.

  ## The write discipline

  `Ouroboros.Web.Publication`'s, exactly — an exclusive temporary inode, chmodded `0600`
  *before* any bytes reach it, synced, and renamed into place. This file holds nothing
  secret, but it sits in the operator's data directory beside two files that do, and one
  write discipline in a directory is easier to keep right than two. A preplanted symlink is
  a refusal rather than a write through it.

  A failed write is **swallowed** by the caller and logged here. It happens after a session
  has already started; failing the operator's start over a preference that could not be
  remembered would be the wrong trade by a wide margin.
  """

  require Logger

  alias Ouroboros.DataDir

  @filename "web.prefs.json"

  # The five keys `interactive.start` takes that a person makes a standing choice about.
  # `id` is deliberately absent: it is minted per form and idempotency is the whole reason
  # it exists, so a remembered one would adopt a session the operator already finished.
  @keys ["provider", "model", "workspace", "sandbox_mode", "reasoning_effort"]

  # Closed vocabularies, restated here rather than reached for through the LiveView layer:
  # this module is read at mount and must not depend on anything that draws.
  @sandbox_modes ["read_only", "workspace_write", "unrestricted"]
  @efforts ["low", "medium", "high"]

  # A preferences file is five short strings. Anything approaching this is not one, and
  # reading it into memory to find that out is what the bound is for.
  @max_bytes 64 * 1024

  # A workspace path can be long; nothing else here can. One ceiling for all of them,
  # generous enough that no honest value meets it.
  @max_value_bytes 4 * 1024

  @doc "The keys this file may hold, in the order the form asks about them."
  @spec keys() :: [String.t()]
  def keys, do: @keys

  @doc "Where the preferences live for one data directory."
  @spec path(Path.t()) :: Path.t()
  def path(data_dir) when is_binary(data_dir), do: Path.join(data_dir, @filename)

  @doc """
  The stored defaults, or `%{}` — never anything else, and never a raise.

  Keys are the strings above; every value is a non-empty binary that has already been
  checked against the vocabulary its parameter admits.
  """
  @spec read(Path.t() | nil) :: %{optional(String.t()) => String.t()}
  def read(data_dir) when is_binary(data_dir) and data_dir != "" do
    file = path(data_dir)

    case File.lstat(file) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_bytes ->
        decode(file)

      {:ok, %File.Stat{type: :regular}} ->
        quietly(file, "it is larger than #{@max_bytes} bytes")

      {:ok, %File.Stat{type: type}} ->
        quietly(file, "it is a #{type}, not a regular file")

      # Absent is the first-run state, not a fault, and says nothing.
      {:error, :enoent} ->
        %{}

      {:error, reason} ->
        quietly(file, "it could not be read: #{inspect(reason)}")
    end
  end

  def read(_absent), do: %{}

  @doc """
  Write the stated keys, atomically and privately.

  `stated` is `start_params/2`'s map: anything outside `keys/0` is dropped, and so is any
  value that is not a non-empty binary the parameter's vocabulary admits. Returns `:ok`
  even when there was nothing worth writing.
  """
  @spec write(Path.t() | nil, map()) :: :ok | {:error, term()}
  def write(data_dir, stated) when is_binary(data_dir) and data_dir != "" and is_map(stated) do
    case sanitize(stated) do
      empty when map_size(empty) == 0 ->
        :ok

      prefs ->
        try do
          publish(path(data_dir), data_dir, prefs)
        rescue
          error ->
            # Never the caller's problem: this runs after a session has already started.
            Logger.info(
              "web could not write #{path(data_dir)}: #{Exception.message(error)}; " <>
                "the new-session form will start from wherever it started this time"
            )

            {:error, error}
        end
    end
  end

  def write(_absent, _stated), do: :ok

  # ------------------------------------------------------------------------------------
  # Reading
  # ------------------------------------------------------------------------------------

  defp decode(file) do
    with {:ok, encoded} <- File.read(file),
         {:ok, decoded} when is_map(decoded) <- JSON.decode(encoded) do
      sanitize(decoded)
    else
      {:ok, _not_an_object} ->
        quietly(file, "it does not hold a JSON object")

      {:error, reason} ->
        quietly(file, "it is not readable JSON: #{inspect(reason)}")
    end
  end

  # One line, at info, naming the file and what is wrong with it. Not a warning: nothing is
  # broken, a form will simply open with no defaults in it, which is where it opened before
  # this file existed. Not silent either — an operator whose remembered workspace stopped
  # coming back is owed the reason.
  defp quietly(file, why) do
    Logger.info("web is ignoring #{file} because #{why}; the new-session form has no defaults")
    %{}
  end

  # ------------------------------------------------------------------------------------
  # Validation, shared by both directions
  # ------------------------------------------------------------------------------------

  defp sanitize(map) do
    @keys
    |> Enum.reduce(%{}, fn key, kept ->
      case validate(key, Map.get(map, key)) do
        nil -> kept
        value -> Map.put(kept, key, value)
      end
    end)
  end

  defp validate("sandbox_mode", value), do: one_of(value, @sandbox_modes)
  defp validate("reasoning_effort", value), do: one_of(value, @efforts)

  defp validate(_key, value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      trimmed when byte_size(trimmed) > @max_value_bytes -> nil
      trimmed -> trimmed
    end
  end

  defp validate(_key, _value), do: nil

  defp one_of(value, allowed) when is_binary(value), do: if(value in allowed, do: value)
  defp one_of(_value, _allowed), do: nil

  # ------------------------------------------------------------------------------------
  # Writing
  # ------------------------------------------------------------------------------------

  defp publish(file, data_dir, prefs) do
    DataDir.ensure_private!(data_dir)

    tmp =
      file <>
        ".tmp-#{System.unique_integer([:positive, :monotonic])}-" <>
        Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    contents = JSON.encode_to_iodata!(prefs)

    try do
      # The exclusive empty inode makes a preplanted symlink a refusal. Its mode is private
      # before any bytes are written, and the descriptor is synced before the rename.
      File.write!(tmp, "", [:exclusive, :sync])
      File.chmod!(tmp, 0o600)
      before = File.lstat!(tmp, time: :posix)

      File.open!(tmp, [:write, :binary], fn io ->
        IO.binwrite(io, contents)
        :ok = :file.sync(io)
      end)

      unless same_file?(before, File.lstat!(tmp, time: :posix)) do
        raise "web preferences temporary inode changed while it was written"
      end

      File.rename!(tmp, file)
      :ok
    rescue
      error ->
        _ = File.rm(tmp)
        reraise error, __STACKTRACE__
    end
  end

  defp same_file?(left, right) do
    left.uid == right.uid and left.major_device == right.major_device and
      left.inode == right.inode
  end
end
