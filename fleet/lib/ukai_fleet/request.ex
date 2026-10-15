defmodule UkaiFleet.InvalidRequest do
  @moduledoc """
  Malformed caller input, refused before anything is written on its behalf.

  The controller and worker answer it with `{:error, reply(message)}` and keep
  running. Any other exception still stops them: its persistence outcome is unknown.
  """
  defexception message: "invalid request"

  @doc """
  The error a refusal answers with: the stable reason and the check that failed.

  `detail` is fixed text naming the check, never the caller's value, so a refusal
  cannot echo argv or other request content back.
  """
  def reply(detail), do: %{"reason" => "invalid_request", "detail" => detail}
end

defmodule UkaiFleet.Request do
  @moduledoc "Bounded trusted-operator batch requests. Raw argv is never checkpointed."
  alias UkaiFleet.InvalidRequest

  @keys ~w(schema request_id on dir jail launch observe evidence limits capture capture_limit tags argv)
  @defaults %{
    "on" => "auto",
    "jail" => "tool",
    "observe" => "on",
    "evidence" => "strict",
    "capture" => [],
    "limits" => [],
    "tags" => [],
    "capture_limit" => 1_048_576
  }

  def validate!(input) when is_map(input) do
    if Map.keys(input) -- @keys != [], do: invalid!("unknown request field")

    # JSON null asks for the default. Every check below reads the merged map, so the
    # request returned, digested and turned into argv is exactly the one validated.
    request =
      Map.merge(@defaults, input, fn _key, default, value ->
        if is_nil(value), do: default, else: value
      end)

    if request["schema"] != "ukai.fleet.request/1", do: invalid!("unsupported request schema")
    scalar!("request_id", request["request_id"], 256)
    scalar!("on", request["on"], 128)
    argv = request["argv"]
    if not is_list(argv) or argv == [] or length(argv) > 4096, do: invalid!("invalid argv")
    Enum.each(argv, &scalar!("argv element", &1, 65536, true))
    if IO.iodata_length(UkaiFleet.JSON.encode(input)) > 524_288, do: invalid!("request too large")

    for key <- ["dir", "jail", "launch"], not is_nil(request[key]) do
      scalar!(key, request[key], 4096)
    end

    if request["dir"] && Path.type(request["dir"]) != :absolute,
      do: invalid!("directory must be absolute")

    if request["observe"] not in ["on", "off"], do: invalid!("invalid observation mode")

    if request["evidence"] not in ["strict", "best-effort"],
      do: invalid!("invalid evidence mode")

    for key <- ["limits", "capture", "tags"] do
      values = request[key]

      if not is_list(values) or length(values) > 16 or Enum.uniq(values) != values,
        do: invalid!("invalid #{key} list")

      Enum.each(values, &scalar!("#{key} entry", &1, 256))
    end

    if Enum.any?(request["capture"], &(&1 not in ["stdout", "stderr"])),
      do: invalid!("invalid capture")

    limit = request["capture_limit"]

    if not is_integer(limit) or limit < 0 or limit > 16_777_216,
      do: invalid!("invalid capture limit")

    request
  end

  def validate!(_), do: invalid!("request must be an object")

  @doc "Whether `key` has the shape of a job id the controller derives."
  def job?(key), do: is_binary(key) and Regex.match?(~r/^job_[0-9a-f]{64}$/, key)

  @doc "Refuses malformed caller input; see `UkaiFleet.InvalidRequest`."
  def invalid!(message), do: raise(InvalidRequest, message)

  # `name` is the field's own name, so the refusal says which field failed.
  defp scalar!(name, value, max, empty \\ false) do
    unless is_binary(value) and String.valid?(value) and byte_size(value) <= max and
             (empty or value != "") and not String.contains?(value, <<0>>),
           do: invalid!("invalid " <> name)
  end

  def policy(request, workspace) do
    [
      "--profile",
      request["jail"],
      "--workspace",
      workspace,
      "--observe",
      request["observe"],
      "--evidence",
      request["evidence"]
    ] ++
      option("--launch", request["launch"]) ++ repeated("--limit", request["limits"])
  end

  def ledger(request, workspace, config, key) do
    [
      "--data-dir",
      config["data"],
      "run",
      "--request-id",
      key,
      "--jail-bin",
      config["jail_bin"],
      "--jail",
      request["jail"],
      "--workspace",
      workspace,
      "--observe",
      request["observe"],
      "--evidence",
      request["evidence"],
      "--io",
      "batch",
      "--detach",
      "--json",
      "--capture-limit",
      to_string(request["capture_limit"])
    ] ++
      option("--launch", request["launch"]) ++
      repeated("--limit", request["limits"]) ++
      repeated("--capture", request["capture"]) ++ repeated("--tag", request["tags"])
  end

  defp option(_, nil), do: []
  defp option(name, value), do: [name, value]
  defp repeated(name, values), do: Enum.flat_map(values, &[name, &1])
end
