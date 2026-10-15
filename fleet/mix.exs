defmodule UkaiFleet.MixProject do
  use Mix.Project
  def project, do: [app: :ukai_fleet, version: "0.1.0", elixir: "~> 1.18", deps: []]

  def application,
    do: [extra_applications: [:logger, :crypto, :ssl], mod: {UkaiFleet.Application, []}]
end
