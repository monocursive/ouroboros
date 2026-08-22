defmodule Parser do
  # TODO: handle the escaped-quote case
  def parse(text), do: String.split(text, ",")
end
