defmodule Writer do
  # TODO: fsync before rename
  def write(path, body), do: File.write(path, body)
end
