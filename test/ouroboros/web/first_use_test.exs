defmodule Ouroboros.Web.FirstUseTest do
  use ExUnit.Case, async: false
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest
  alias Ouroboros.Web.{Config, Launch, Prefs}
  alias Ouroboros.Web.Live.NewSession
  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("w", 40)
  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    Ouroboros.DataDir.ensure_private!(dir)
    Ouroboros.Test.FirstUseIsolation.setup(dir)
    File.write!(Path.join(dir, "gateway.token"), @token)
    File.chmod!(Path.join(dir, "gateway.token"), 0o600)

    start_supervised!(
      {Ouroboros.Web, config: Config.new!(data_dir: dir, scope: :operate), server: false}
    )

    %{dir: dir}
  end

  defp launch(path) do
    conn =
      get(build_conn(), "/auth?" <> URI.encode_query(%{"token" => @token, "workspace" => path}))

    [location] = Plug.Conn.get_resp_header(conn, "location")
    refute location =~ @token
    conn = recycle(conn)
    {:ok, view, html} = live(conn, location)
    {conn, view, html}
  end

  defp form(view), do: :sys.get_state(view.pid).socket.assigns.form

  test "auth rejects a wrong token before using project context and POST keeps its destination",
       %{dir: dir} do
    conn =
      get(build_conn(), "/auth?" <> URI.encode_query(%{"token" => "wrong", "workspace" => dir}))

    assert conn.status == 401
    assert conn.resp_cookies == %{}
    assert Plug.Conn.get_resp_header(conn, "location") == []

    conn =
      build_conn()
      |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
      |> post("/auth?workspace=%2Fignored", URI.encode_query(%{"token" => @token}))

    assert Plug.Conn.get_resp_header(conn, "location") == ["/"]
  end

  test "nonexistent and regular-file folders refuse at start without changing preferences", %{
    dir: dir
  } do
    Application.put_env(:ouroboros, :native_model, "scripted:browser")
    prefs = %{"workspace" => dir}
    Prefs.write(dir, prefs)
    file = Path.join(dir, "regular-file")
    File.write!(file, "fixture")

    for path <- [file, Path.join(dir, "absent-directory")] do
      {_conn, view, _} = launch(path)

      params =
        NewSession.start_params(
          form(view),
          NewSession.model_field(Ouroboros.Models.list(), form(view))
        )

      assert {:error, -32006, "the runtime refused the call", ["invalid_workspace", ^path]} =
               Ouroboros.Web.Call.call(:operate, "interactive.start", params)

      render_submit(view, "start", %{})
      assert has_element?(view, ".ouro-new-refusal")
      assert Prefs.read(dir) == prefs
      assert :sys.get_state(view.pid).socket.assigns.started_id == nil
    end
  end

  test "authenticated invocation overrides a different daemon cwd, then explicit edits win", %{
    dir: dir
  } do
    path = Path.join(dir, "repo + & % # é ")
    File.mkdir!(path)
    refute path == File.cwd!()
    {conn, view, _} = launch(path)
    assert form(view).workspace == path
    assert NewSession.start_params(form(view), :unsupported)["workspace"] == path
    assert Prefs.read(dir) == %{}
    render_change(view, "change", %{"workspace" => dir})
    assert form(view).workspace == dir
    # Another launch against the same endpoint is invocation-local, not daemon state.
    {_conn2, second, _} = launch(path)
    assert form(second).workspace == path
    assert form(view).workspace == dir
    {:ok, plain, _} = live(conn, "/new")
    assert form(plain).workspace == ""
    assert has_element?(plain, "button[type=submit][disabled]")
    render_submit(plain, "start", %{})
    assert render(plain) =~ "Choose a project folder"
  end

  test "saved explicit choices survive without handoff; opening a handoff writes no prefs", %{
    dir: dir
  } do
    prefs = %{
      "workspace" => dir,
      "model" => "openai_codex:fixture-astra",
      "reasoning_effort" => "xhigh"
    }

    Prefs.write(dir, prefs)
    before = File.read!(Prefs.path(dir))
    {conn, view, _} = launch(dir <> "/other")
    assert form(view).workspace == dir <> "/other"
    assert form(view).model_text == prefs["model"]
    assert form(view).effort == "xhigh"
    assert File.read!(Prefs.path(dir)) == before
    {:ok, saved, _} = live(conn, "/new")
    assert form(saved).workspace == dir
    assert form(saved).effort == "xhigh"
    Prefs.write(dir, %{"workspace" => dir <> "/trailing "})
    assert Prefs.read(dir)["workspace"] == dir <> "/trailing "
  end

  test "configured and saved missing models are ordinary exact choices with xhigh", %{dir: dir} do
    id = "openai_codex:fixture-astra"
    Application.put_env(:ouroboros, :native_model, id)
    {_conn, view, html} = launch(dir)
    assert html =~ "Configured; catalogue metadata unavailable; access not verified"
    assert has_element?(view, ~s(option[value="catalog:#{id}"]))

    render_change(view, "change", %{
      "model_search" => "astra",
      "model_choice" => "catalog:" <> id,
      "effort" => "xhigh"
    })

    render_change(view, "change", %{"model_search" => "no match", "effort" => "xhigh"})
    assert has_element?(view, ~s(option[value="catalog:#{id}"][selected]))
    field = NewSession.model_field(Ouroboros.Models.list(), form(view))

    assert %{"model" => ^id, "reasoning_effort" => "xhigh", "workspace" => ^dir} =
             NewSession.start_params(form(view), field)

    Prefs.write(dir, %{
      "model" => "openai_codex:saved-missing",
      "reasoning_effort" => "xhigh",
      "workspace" => dir
    })

    {_conn, saved, _} = launch(dir)
    assert has_element?(saved, ~s(option[value="catalog:openai_codex:saved-missing"][selected]))
    assert form(saved).effort == "xhigh"
  end

  test "local aliases retain settings; remote saved choices cannot carry over", %{dir: dir} do
    for machine <- [to_string(node()), "remote-unavailable"] do
      Prefs.write(dir, %{
        "machine" => machine,
        "workspace" => "/old",
        "model" => "openai_codex:saved-missing",
        "reasoning_effort" => "xhigh"
      })

      {_conn, view, _} = launch(dir)
      assert form(view).machine == ""
      assert form(view).workspace == dir

      if machine == to_string(node()),
        do: assert(form(view).effort == "xhigh"),
        else: assert(form(view).effort == nil)
    end
  end

  test "invalid handoffs never fall back to a saved project or become redirects", %{dir: dir} do
    Prefs.write(dir, %{"workspace" => dir})

    for invalid <- ["", "relative", "//host\n", "/nul" <> <<0>>, String.duplicate("/", 4097)] do
      assert Launch.workspace(invalid) == :error
      {_conn, view, _} = launch(invalid)
      assert form(view).workspace == ""
      assert has_element?(view, "button[type=submit][disabled]")
    end

    assert Launch.workspace(%{"nested" => dir}) == :error
    assert Launch.workspace(<<255>>) == :error
    assert Launch.destination(%{"next" => "https://example.com"}) == "/"
    {conn, _, _} = launch(dir)

    {:ok, conflict, _} =
      live(conn, "/new?" <> URI.encode_query(%{"workspace" => dir, "machine" => "elsewhere"}))

    assert form(conflict).workspace == ""
    assert form(conflict).machine == ""
    {:ok, malformed, _} = live(conn, "/new?workspace[nested]=bad")
    assert form(malformed).workspace == ""
  end
end
