defmodule Ouroboros.ID do
  @moduledoc """
  Lowercase UUIDv7 identifiers with a millisecond timestamp and 74 random bits.

  A backward wall clock is represented faithfully. IDs remain unique probabilistically
  through cryptographic randomness, including within one millisecond; no global or
  same-millisecond ordering is promised. Event sequencing uses explicit cursors.
  """

  @type t :: String.t()

  @spec generate!() :: t()
  def generate!, do: generate!(fn -> System.system_time(:millisecond) end)

  @doc false
  @spec generate!((-> integer())) :: t()
  def generate!(clock) when is_function(clock, 0) do
    timestamp = clock.()

    unless is_integer(timestamp) and timestamp >= 0 and timestamp <= 0xFFFFFFFFFFFF,
      do: raise(ArgumentError, "UUIDv7 timestamp out of range")

    <<random_a::12, random_b::62, _unused::6>> = :crypto.strong_rand_bytes(10)
    binary = <<timestamp::48, 7::4, random_a::12, 2::2, random_b::62>>

    <<a::binary-size(8), b::binary-size(4), c::binary-size(4), d::binary-size(4),
      e::binary-size(12)>> = Base.encode16(binary, case: :lower)

    Enum.join([a, b, c, d, e], "-")
  end
end
