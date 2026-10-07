defmodule OuroFleet.Request do
  @moduledoc "Bounded trusted-operator batch requests. Raw argv is never checkpointed."
  @keys ~w(schema request_id on dir jail launch observe evidence limits capture capture_limit tags argv)

  def validate!(request) when is_map(request) do
    if Map.keys(request) -- @keys != [], do: raise("unknown request field")
    if request["schema"] != "ouro.fleet.request/1", do: raise("unsupported request schema")
    scalar!(request["request_id"], 256)
    scalar!(request["on"] || "auto", 128)
    argv = request["argv"]
    if not is_list(argv) or argv == [] or length(argv) > 4096, do: raise("invalid argv")
    Enum.each(argv, &scalar!(&1, 65536, true))
    if IO.iodata_length(OuroFleet.JSON.encode(request)) > 524_288, do: raise("request too large")

    for key <- ["dir", "jail", "launch"] do
      if request[key], do: scalar!(request[key], 4096)
    end

    if request["dir"] && Path.type(request["dir"]) != :absolute,
      do: raise("directory must be absolute")

    if (request["observe"] || "on") not in ["on", "off"], do: raise("invalid observation mode")

    if (request["evidence"] || "strict") not in ["strict", "best-effort"],
      do: raise("invalid evidence mode")

    for key <- ["limits", "capture", "tags"] do
      values = request[key] || []

      if not is_list(values) or length(values) > 16 or Enum.uniq(values) != values,
        do: raise("invalid option list")

      Enum.each(values, &scalar!(&1, 256))
    end

    if Enum.any?(request["capture"] || [], &(&1 not in ["stdout", "stderr"])),
      do: raise("invalid capture")

    limit = request["capture_limit"] || 1_048_576

    if not is_integer(limit) or limit < 0 or limit > 16_777_216,
      do: raise("invalid capture limit")

    Map.merge(
      %{
        "on" => "auto",
        "jail" => "tool",
        "observe" => "on",
        "evidence" => "strict",
        "capture" => [],
        "limits" => [],
        "tags" => [],
        "capture_limit" => 1_048_576
      },
      request
    )
  end

  def validate!(_), do: raise("request must be an object")

  defp scalar!(value, max, empty \\ false) do
    unless is_binary(value) and String.valid?(value) and byte_size(value) <= max and
             (empty or value != "") and not String.contains?(value, <<0>>),
           do: raise("invalid text field")
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
