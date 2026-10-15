[path] = System.argv()
config = UkaiFleet.Store.read!(UkaiFleet.Boot.private!(path))
UkaiFleet.Boot.start(config, true)
input = IO.binread(:stdio, 524289)
if not is_binary(input) or byte_size(input) > 524288, do: raise("invalid client frame")
request = UkaiFleet.JSON.decode(input)
message = case request do
  %{"operation" => "run", "request" => body} -> {:run, body}
  %{"operation" => "status", "job" => nil} -> :status
  %{"operation" => "status", "job" => job} -> {:status, job}
  %{"operation" => "kill", "job" => job} -> {:kill, job}
  %{"operation" => "ledger", "job" => job, "flags" => flags} -> {:ledger, job, flags}
  %{"operation" => "doctor"} -> :doctor
  _ -> raise("unsupported operation")
end
result = UkaiFleet.Client.call(String.to_atom(config["controller"]), message)
case result do
  {:ok, value} -> IO.puts(UkaiFleet.JSON.encode(%{"ok" => true, "result" => value}))
  {:error, reason} -> IO.puts(UkaiFleet.JSON.encode(%{"ok" => false, "error" => reason})); System.halt(1)
end
