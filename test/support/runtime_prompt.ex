defmodule Ouroboros.Test.Prompt do
  @moduledoc false

  @doc """
  True when `prompt` is a captured runtime envelope followed by the original user text.

  The envelope is pinned when the durable task/session is admitted. The user text is
  still a suffix and the reserved delimiters are still present.
  """
  @spec wrapped?(term(), String.t()) :: boolean()
  def wrapped?(prompt, user_text) when is_binary(prompt) and is_binary(user_text) do
    String.contains?(prompt, "<ouroboros-runtime") and
      String.contains?(prompt, "</ouroboros-runtime>") and
      String.ends_with?(prompt, user_text)
  end

  def wrapped?(_prompt, _user_text), do: false
end
