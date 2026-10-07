[path] = System.argv()
config = OuroFleet.Store.read!(OuroFleet.Boot.private!(path))
OuroFleet.Boot.start(config, true)
input = IO.binread(:stdio, 524289)
if not is_binary(input) or byte_size(input) > 524288, do: raise("invalid client frame")
request = OuroFleet.JSON.decode(input)
message = case request do
  %{"operation" => "run", "request" => body} -> {:run, body}
  %{"operation" => "status", "job" => nil} -> :status
  %{"operation" => "status", "job" => job} -> {:status, job}
  %{"operation" => "kill", "job" => job} -> {:kill, job}
  %{"operation" => "ledger", "job" => job, "flags" => flags} -> {:ledger, job, flags}
  %{"operation" => "doctor"} -> :doctor
  _ -> raise("unsupported operation")
end
result = try do
  {:ok, %{"schema" => "ouro.fleet.rpc/1", "run" => "ouro.ledger.run/1"}} =
    :erpc.call(String.to_atom(config["controller"]), OuroFleet.Controller, :call, [:version], 10_000)
  :erpc.call(String.to_atom(config["controller"]), OuroFleet.Controller, :call, [message], 185_000)
catch
  _, _ -> {:error, "controller_unreachable_or_reply_lost_retry_same_request"}
end
case result do
  {:ok, value} -> IO.puts(OuroFleet.JSON.encode(%{"ok" => true, "result" => value}))
  {:error, reason} -> IO.puts(OuroFleet.JSON.encode(%{"ok" => false, "error" => reason})); System.halt(1)
end
