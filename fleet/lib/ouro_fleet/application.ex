defmodule OuroFleet.Application do
  use Application
  alias OuroFleet.Store

  def start(_type, _args) do
    children =
      case System.get_env("OURO_FLEET_CONFIG") do
        nil ->
          []

        path ->
          config = Store.read!(path)

          unless config["schema"] == "ouro.fleet.node/1" and is_list(config["members"]) and
                   length(config["members"]) in 1..64 and config["fleet_id"] != "",
                 do: raise("invalid fleet configuration")

          for member <- config["members"] do
            unless Regex.match?(~r/^ouro-[a-z0-9_-]+@[a-z0-9.:-]+$/, member["node"]),
              do: raise("invalid node")
          end

          Store.directory!(config["state"])
          # Supervisor restarts all consumers when the lock guard dies; a consumer
          # can never keep writing while another VM acquires the released flock.
          [
            {OuroFleet.Lock, Path.join(config["state"], "writer.lock")},
            {OuroFleet.Worker, config},
            {OuroFleet.Controller, config}
          ]
      end

    Supervisor.start_link(children, strategy: :one_for_all, name: OuroFleet.Supervisor)
  end
end
