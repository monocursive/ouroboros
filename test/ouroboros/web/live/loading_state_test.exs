defmodule Ouroboros.Web.Live.LoadingStateTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Live.LoadingState

  @app_js File.read!("priv/static/web/app.js")

  test "renders a nine-cell drive loader with one quiet elapsed clock" do
    html = render_component(&LoadingState.loading/1, %{id: "working", label: "Agent working"})

    assert html =~ ~s(role="status")
    assert html =~ "Agent working"
    assert length(Regex.scan(~r/data-cell=/, html)) == 9
    assert html =~ ~s(phx-hook="ElapsedTimer")
    assert html =~ ~s(phx-update="ignore")
    assert html =~ ~s|aria-hidden="true">0.0s</span>|
  end

  test "offers round dots and a perimeter orbit without changing its contract" do
    dots = render_component(&LoadingState.loading/1, %{id: "dots", variant: :dots})
    orbit = render_component(&LoadingState.loading/1, %{id: "orbit", variant: :orbit})

    assert length(Regex.scan(~r/ouro-loader-cell-round/, dots)) == 9
    assert orbit =~ "--ouro-loader-duration: 950ms"
    assert length(Regex.scan(~r/ouro-loader-cell-active/, orbit)) == 8
  end

  test "the asset registers a monotonic local timer and cleans it up" do
    assert @app_js =~ "ElapsedTimer: ElapsedTimer"
    assert @app_js =~ "performance.now()"
    assert @app_js =~ "window.setInterval(this.paint, 100)"
    assert @app_js =~ "window.clearInterval(this.timer)"
  end
end
