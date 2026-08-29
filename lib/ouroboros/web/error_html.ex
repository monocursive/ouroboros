defmodule Ouroboros.Web.ErrorHTML do
  @moduledoc """
  What an error looks like when there is nothing useful to say.

  The status line and nothing else. `debug_errors` is off on this endpoint, and an
  operator surface is the wrong place to render a stack trace into a browser that may be
  standing on somebody's tailnet.
  """

  @doc false
  def render(template, _assigns) do
    Phoenix.Controller.status_message_from_template(template)
  end
end
