defmodule Parser do
  def tokenize(text), do: String.split(text)
  def parse(tokens), do: {:ok, tokens}
end
