defmodule Ouroboros.Web.Live.NewSessionLiveTest do
  @moduledoc """
  The new-session form: what it offers, what it says it will send, and what it sends.

  ## Two halves, deliberately

  The rules live in `Ouroboros.Web.Live.NewSession`, which has no socket in it, so most of
  this file drives that module directly with fixtures it fully controls — a runtime's
  provider list is a property of the machine the suite runs on, and a test that asserted
  "claude is dimmed here" would be asserting somebody's PATH.

  The rest drives the LiveView against the **real** methods through `Ouroboros.Web.Call`:
  `runtime.providers` and `runtime.models` answer from this node, and `workspace.browse`
  walks real directories under a root this file creates and points
  `:workspace_allowed_roots` at. Those assertions are therefore written against structure
  and against the form's own state, never against a particular provider being installed.

  **Not** covered here: an actually-started session. `interactive.start` spawns a provider,
  and a test that let it would be testing the interactive plane. What is covered is the
  exact envelope the form builds — asserted on the form the operator's clicks produced —
  and the deck's half of the `?open` contract, driven with a coordinator registered in the
  real registry the way `Ouroboros.Web.Live.DeckLiveTest` does it.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Gateway.Methods.Browse
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.NewSession

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("t", 40)
  @cookie "_ouroboros_web"

  # ------------------------------------------------------------------------------------
  # Fixtures for the pure half
  # ------------------------------------------------------------------------------------

  defp probed(name, status), do: %{provider: name, spec: %{}, status: status, error: nil}

  defp ready(name),
    do: probed(name, %{installed: true, compatible: true, version: "1.0", executable: "/bin/x"})

  defp missing(name),
    do: probed(name, %{installed: false, compatible: false, version: nil, executable: nil})

  defp catalogue(rows), do: %{source: "llm_db", epoch: 1, limit: 50, providers: rows}

  defp provider_row(name, opts \\ []) do
    %{
      provider: name,
      catalog: :openai,
      default: Keyword.get(opts, :default),
      model_option: Keyword.get(opts, :model_option, true),
      total: Keyword.get(opts, :total, 0),
      models: Keyword.get(opts, :models, [])
    }
  end

  defp model(id, opts \\ []) do
    %{
      id: id,
      name: Keyword.get(opts, :name),
      context_window: Keyword.get(opts, :context_window),
      max_output_tokens: nil,
      release_date: nil,
      reasoning_efforts: ["low", "medium", "high"],
      pricing: nil
    }
  end

  # ------------------------------------------------------------------------------------
  # The provider picker
  # ------------------------------------------------------------------------------------

  describe "provider rows" do
    test "a probe that found no executable is dimmed, annotated, and still offered" do
      rows = NewSession.provider_rows([ready(:claude), missing(:gemini)])

      assert [%{name: "claude", detected?: true, note: nil}, gemini] = rows
      assert gemini.name == "gemini"
      refute gemini.detected?
      assert gemini.note == "no executable found"

      # Selectable is the whole point: the row exists, so the form can send it.
      assert Enum.map(rows, & &1.name) == ["claude", "gemini"]
    end

    test "a probe that did not run says that, rather than borrowing 'no executable'" do
      rows = NewSession.provider_rows([probed(:kimi, nil) |> Map.put(:error, :probe_timeout)])

      assert [%{detected?: false, note: "the probe did not answer: probe_timeout"}] = rows
    end

    test "an installed-but-incompatible probe names the version it found" do
      status = %{installed: true, compatible: false, version: "0.1", executable: "/bin/x"}

      assert [%{detected?: false, note: note}] = NewSession.provider_rows([probed(:pi, status)])
      assert note == "version 0.1 is not one this build can drive"
    end

    test "the footnote appears only when something is dimmed, and says what a probe knows" do
      assert NewSession.provider_footnote(NewSession.provider_rows([ready(:claude)])) == nil

      footnote = NewSession.provider_footnote(NewSession.provider_rows([missing(:gemini)]))

      assert footnote ==
               "Dimmed entries are ones whose probe found no executable. " <>
                 "The runtime decides whether a session starts."
    end
  end

  # ------------------------------------------------------------------------------------
  # The model control
  # ------------------------------------------------------------------------------------

  describe "the model field" do
    test "an adapter that normalizes no model option gets a control with nothing in it" do
      field =
        NewSession.model_field(catalogue([provider_row(:amp, model_option: false)]), "amp")

      assert field == :unsupported
      assert NewSession.model_intent(field, :runtime_default, "").send == nil
    end

    test "no catalogue, an unnamed provider, and no provider all fall back to free text" do
      assert NewSession.model_field(nil, "claude") == {:text, nil}

      assert NewSession.model_field(catalogue([]), nil) ==
               {:text, "choose a provider to see its models"}

      assert NewSession.model_field(catalogue([]), "claude") ==
               {:text, "this runtime's model list does not mention claude"}
    end

    test "rows put Runtime default first and Custom last, with name and context beside each" do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native,
              default: "openai_codex:gpt-5.6-sol",
              total: 2,
              models: [
                model("openai_codex:gpt-5.6-sol", name: "GPT-5.6 Sol", context_window: 1_050_000),
                model("bare-id")
              ]
            )
          ]),
          "native"
        )

      assert {:rows, rows, 2} = field
      assert Enum.map(rows, & &1.choice) |> List.first() == :runtime_default
      assert Enum.map(rows, & &1.choice) |> List.last() == :custom

      assert [first, sol, bare, last] = rows
      assert first.label == "Runtime default · openai_codex:gpt-5.6-sol"
      assert sol.label == "openai_codex:gpt-5.6-sol"
      assert sol.detail == "GPT-5.6 Sol · 1.1M context"
      # A row the snapshot said nothing else about shows only its id.
      assert bare.detail == nil
      assert last.label == "Custom…"
    end

    test "a provider with no configured default says so without inventing one" do
      assert {:rows, [first | _rest], 0} =
               NewSession.model_field(catalogue([provider_row(:pi)]), "pi")

      assert first.label == "Runtime default"
    end
  end

  describe "searching the model rows" do
    setup do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native,
              total: 3,
              models: [
                model("openai_codex:gpt-5.6-sol", name: "GPT-5.6 Sol"),
                model("gpt-5.6-mini", name: "GPT-5.6 Mini"),
                model("o4-thinker", name: "Deep Thinker")
              ]
            )
          ]),
          "native"
        )

      {:ok, field: field}
    end

    test "filters on the id and on the vendor's own name", %{field: field} do
      assert {:rows, rows, 3} = NewSession.search(field, "thinker", :runtime_default)
      assert Enum.map(rows, & &1.label) == ["Runtime default", "o4-thinker", "Custom…"]

      assert {:rows, mini, 3} = NewSession.search(field, "MINI", :runtime_default)
      assert Enum.map(mini, & &1.label) == ["Runtime default", "gpt-5.6-mini", "Custom…"]
    end

    test "never filters away the two framing rows", %{field: field} do
      assert {:rows, rows, 3} = NewSession.search(field, "nothing matches this", :runtime_default)
      assert Enum.map(rows, & &1.choice) == [:runtime_default, :custom]
    end

    test "never filters away the row the operator has chosen", %{field: field} do
      chosen = {:catalog, "o4-thinker"}

      assert {:rows, rows, 3} = NewSession.search(field, "mini", chosen)

      # Both the match and the choice survive, in the catalogue's own order: a `<select>`
      # whose selected value is absent from its options would draw some other row, which is
      # the exact disagreement between widget and state this design exists to make
      # impossible.
      assert Enum.map(rows, & &1.choice) == [
               :runtime_default,
               {:catalog, "gpt-5.6-mini"},
               chosen,
               :custom
             ]
    end
  end

  # ------------------------------------------------------------------------------------
  # The one property: the sentence and the payload come from one function
  # ------------------------------------------------------------------------------------

  describe "the hint line and the request" do
    test "say the same thing for every shape the field can take" do
      rows =
        NewSession.model_field(
          catalogue([
            provider_row(:native, default: "d", total: 1, models: [model("openai_codex:x")])
          ]),
          "native"
        )

      cases = [
        {:unsupported, :runtime_default, "",
         {nil, "Sends no model option — this provider does not accept one"}},
        {{:text, nil}, :runtime_default, "  my-build  ", {"my-build", "Sends my-build"}},
        {{:text, nil}, :runtime_default, "   ", {nil, "Sends no model option (runtime default)"}},
        {rows, :runtime_default, "", {nil, "Sends no model option (runtime default)"}},
        {rows, {:catalog, "openai_codex:x"}, "", {"openai_codex:x", "Sends openai_codex:x"}},
        {rows, :custom, " private ", {"private", "Sends private"}},
        {rows, :custom, "  ", {nil, "Sends no model option (runtime default)"}}
      ]

      for {field, choice, typed, {send, hint}} <- cases do
        intent = NewSession.model_intent(field, choice, typed)
        assert intent == %{send: send, hint: hint}

        # And the request reads that same `:send`, rather than recomputing it.
        form = %NewSession{
          NewSession.new()
          | provider: "native",
            model_choice: choice,
            model_text: typed
        }

        assert {:ok, params} = NewSession.start_params(form, field)
        assert Map.get(params, "model") == send
      end
    end

    test "an empty Custom field sends nothing and says so, rather than implying a model" do
      field = NewSession.model_field(catalogue([provider_row(:pi)]), "pi")
      intent = NewSession.model_intent(field, :custom, "")

      assert intent.send == nil
      assert intent.hint == "Sends no model option (runtime default)"
    end
  end

  # ------------------------------------------------------------------------------------
  # The envelope
  # ------------------------------------------------------------------------------------

  describe "the start envelope" do
    test "an untouched form carries the id and the provider, and nothing else" do
      form = %NewSession{NewSession.new() | provider: "claude"}

      assert {:ok, params} = NewSession.start_params(form, {:text, nil})
      assert Map.keys(params) |> Enum.sort() == ["id", "provider"]
      assert params["provider"] == "claude"
      assert is_binary(params["id"]) and params["id"] != ""

      # Absent, not defaulted: none of the three optional postures is present at all.
      refute Map.has_key?(params, "sandbox_mode")
      refute Map.has_key?(params, "reasoning_effort")
      refute Map.has_key?(params, "model")
      refute Map.has_key?(params, "workspace")

      # And no field the method does not have.
      refute Map.has_key?(params, "title")
    end

    test "every field the operator states appears, with the value they stated" do
      form = %NewSession{
        NewSession.new()
        | provider: "  native  ",
          model_choice: :custom,
          model_text: " openai_codex:x ",
          workspace: "  /srv/work  ",
          sandbox: "workspace_write",
          effort: "high"
      }

      assert {:ok, params} = NewSession.start_params(form, {:text, nil})

      assert Map.keys(params) |> Enum.sort() ==
               ["id", "model", "provider", "reasoning_effort", "sandbox_mode", "workspace"]

      assert params["provider"] == "native"
      assert params["model"] == "openai_codex:x"
      assert params["workspace"] == "/srv/work"
      assert params["sandbox_mode"] == "workspace_write"
      assert params["reasoning_effort"] == "high"
    end

    test "the id survives, so a retry after an unknown outcome adopts the same intent" do
      form = %NewSession{NewSession.new() | provider: "claude"}

      assert {:ok, first} = NewSession.start_params(form, {:text, nil})
      assert {:ok, second} = NewSession.start_params(form, {:text, nil})
      assert first["id"] == second["id"] and first["id"] == form.id
    end

    test "a value outside the gateway's own vocabulary is dropped rather than sent" do
      form = %NewSession{
        NewSession.new()
        | provider: "claude",
          sandbox: "sudo_everything",
          effort: "maximum"
      }

      assert {:ok, params} = NewSession.start_params(form, {:text, nil})
      refute Map.has_key?(params, "sandbox_mode")
      refute Map.has_key?(params, "reasoning_effort")
    end

    test "no provider is refused before anything is built" do
      assert {:error, message} = NewSession.start_params(NewSession.new(), {:text, nil})
      assert message =~ "choose a provider"
    end

    test "each key the envelope may carry is one interactive.start's table accepts" do
      form = %NewSession{
        NewSession.new()
        | provider: "claude",
          model_choice: :custom,
          model_text: "m",
          workspace: "/w",
          sandbox: "read_only",
          effort: "low"
      }

      assert {:ok, params} = NewSession.start_params(form, {:text, nil})

      # Read out of the method table rather than transcribed beside it, so a key this form
      # invents cannot pass by agreeing with a list somebody typed twice.
      {:ok, %{envelope: :closed, params: descriptors}} =
        Ouroboros.Gateway.Methods.params("interactive.start")

      accepted = MapSet.new(descriptors, & &1.name)

      for key <- Map.keys(params) do
        assert MapSet.member?(accepted, key), "interactive.start does not accept #{key}"
      end
    end
  end

  # ------------------------------------------------------------------------------------
  # Stored defaults (W8): `web.prefs.json`
  #
  # The semantics matched here are the **desktop's**, and they are not the ones a first
  # reading of "absent, not defaulted" suggests. `docs/DESKTOP.md:71-74` says "What the file
  # supplies is where the control *starts*; an explicit pick is what gets sent, and an
  # untouched panel with *no stored default* states no posture at all" — and the desktop
  # implements the reading that sentence's last clause forces: `self.new_sandbox
  # .or(configured_sandbox)`, under the comment "the operator's pick, else the stored
  # default, else nothing" (`tui/src/desktop.rs:2264-2269`).
  #
  # So a seeded control is a **stated** control, on all five keys. The alternative — a file
  # that is displayed but not sent — would show an operator one posture and request another,
  # which is the exact failure this module was split out to make impossible.
  # ------------------------------------------------------------------------------------

  describe "stored defaults" do
    test "a form with no stored anything is the form W6 shipped" do
      form = NewSession.new(%{})

      assert form.provider == nil
      assert form.model_choice == :runtime_default
      assert form.workspace == ""
      assert form.sandbox == nil
      assert form.effort == nil

      assert {:error, _no_provider} = NewSession.start_params(form, {:text, nil})
    end

    test "every stored key seeds its control" do
      form =
        NewSession.new(%{
          "provider" => "native",
          "model" => "openai_codex:gpt-5.6-sol",
          "workspace" => "/srv/ouroboros",
          "sandbox_mode" => "workspace_write",
          "reasoning_effort" => "high"
        })

      assert form.provider == "native"
      assert form.model_choice == :custom
      assert form.model_text == "openai_codex:gpt-5.6-sol"
      assert form.workspace == "/srv/ouroboros"
      assert form.sandbox == "workspace_write"
      assert form.effort == "high"
    end

    test "a seeded control is a stated control: every stored key reaches the request" do
      # The decision, pinned. Change this test and you have changed the semantics away
      # from the desktop's.
      form =
        NewSession.new(%{
          "provider" => "native",
          "model" => "openai_codex:gpt-5.6-sol",
          "workspace" => "/srv/ouroboros",
          "sandbox_mode" => "workspace_write",
          "reasoning_effort" => "high"
        })

      assert {:ok, params} = NewSession.start_params(form, {:text, nil})

      assert Map.keys(params) |> Enum.sort() ==
               ["id", "model", "provider", "reasoning_effort", "sandbox_mode", "workspace"]

      assert params["model"] == "openai_codex:gpt-5.6-sol"
      assert params["sandbox_mode"] == "workspace_write"
      assert params["reasoning_effort"] == "high"
    end

    test "a key with no stored value is still absent, not defaulted" do
      form = NewSession.new(%{"provider" => "native", "sandbox_mode" => "read_only"})

      assert {:ok, params} = NewSession.start_params(form, {:text, nil})

      assert Map.keys(params) |> Enum.sort() == ["id", "provider", "sandbox_mode"]
      refute Map.has_key?(params, "reasoning_effort")
      refute Map.has_key?(params, "model")
      refute Map.has_key?(params, "workspace")
    end

    test "the hint line says what the seed will actually send" do
      form = NewSession.new(%{"provider" => "native", "model" => "openai_codex:x"})

      assert NewSession.model_intent(form, {:text, nil}).hint == "Sends openai_codex:x"
    end

    test "a seeded model the catalogue lists is promoted to its own row" do
      form = NewSession.new(%{"provider" => "native", "model" => "seeded-model"})
      field = seeded_field()

      promoted = NewSession.promote(form, field)

      assert promoted.model_choice == {:catalog, "seeded-model"}

      # And it sends exactly what it sent before being promoted: this changes the drawing,
      # never the request.
      assert NewSession.start_params(promoted, field) |> elem(1) |> Map.get("model") ==
               NewSession.start_params(form, field) |> elem(1) |> Map.get("model")
    end

    test "a seeded model no catalogue has heard of stays custom, and is still sent" do
      form = NewSession.new(%{"provider" => "native", "model" => "some-private-build"})
      field = seeded_field()

      assert NewSession.promote(form, field).model_choice == :custom
      assert {:ok, params} = NewSession.start_params(form, field)
      assert params["model"] == "some-private-build"
    end

    test "a provider that accepts no model option sends none, seeded or not" do
      form = NewSession.new(%{"provider" => "native", "model" => "openai_codex:x"})

      assert {:ok, params} = NewSession.start_params(form, :unsupported)
      refute Map.has_key?(params, "model")
    end
  end

  describe "stored defaults, through the page" do
    setup :endpoint_seeded

    test "the form opens where the last successful start left it", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert form(view).provider == "native"
      assert form(view).workspace == "/srv/remembered"
      assert form(view).sandbox == "workspace_write"
      assert form(view).effort == "high"

      assert html =~ ~s(value="/srv/remembered")
    end

    test "and the request it would build carries them", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      assert {:ok, params} = start_params(view)

      assert params["provider"] == "native"
      assert params["workspace"] == "/srv/remembered"
      assert params["sandbox_mode"] == "workspace_write"
      assert params["reasoning_effort"] == "high"
    end

    test "a refused start writes nothing over what is already there", %{conn: conn, dir: dir} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "no-such-provider", "workspace" => "/srv/rejected"})
      html = view |> element("form.ouro-new-form") |> render_submit()

      assert html =~ "must name a provider this node serves"

      # A request the plane refused is not evidence about how the operator likes to work.
      assert Ouroboros.Web.Prefs.read(dir) == %{
               "provider" => "native",
               "workspace" => "/srv/remembered",
               "sandbox_mode" => "workspace_write",
               "reasoning_effort" => "high"
             }
    end
  end

  describe "a corrupt prefs file" do
    setup :endpoint_corrupt

    test "is a form with no defaults rather than a page that will not mount", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert html =~ "New session"
      assert form(view).provider == nil
      assert form(view).workspace == ""
      assert form(view).sandbox == nil
    end
  end

  # ------------------------------------------------------------------------------------
  # Refusals
  # ------------------------------------------------------------------------------------

  describe "refusals" do
    test "a plain refusal is its sentence" do
      assert NewSession.refusal({:error, -32_602, "params.provider must name a provider"}) ==
               %{message: "params.provider must name a provider", detail: nil}
    end

    test "a typed refusal keeps the plane's own message out of data" do
      data = %{
        "reason" => "unsupported_safety_options",
        "message" => "claude reaches an interactive session over the acp transport"
      }

      assert %{message: "the runtime refused the call", detail: detail} =
               NewSession.refusal({:error, -32_006, "the runtime refused the call", data})

      assert detail == "claude reaches an interactive session over the acp transport"
    end

    test "a typed refusal nested under `error` is found there too" do
      data = %{"error" => %{"message" => "sandbox_mode: :default is the only value"}}

      assert %{detail: "sandbox_mode: :default is the only value"} =
               NewSession.refusal({:error, -32_006, "the runtime refused the call", data})
    end

    test "a browse refusal's roots travel as data, because its sentence deliberately omits them" do
      refused =
        {:error, -32_602, "params.path is outside every directory this node browses",
         %{"reason" => "outside_roots", "roots" => ["/home/a", "/srv"]}}

      assert NewSession.refusal_roots(refused) == ["/home/a", "/srv"]
      assert NewSession.refusal_roots({:error, -32_602, "no"}) == []
    end
  end

  # ------------------------------------------------------------------------------------
  # The account card
  # ------------------------------------------------------------------------------------

  describe "the ChatGPT card" do
    test "nothing answered yet is checking, and claims nothing" do
      card = NewSession.account_card(nil, nil)
      assert card.state == :checking
      refute card.usable?
    end

    test "a resolved runtime with no credential is required" do
      read = %{"account" => nil, "requiresOpenaiAuth" => true, "login" => idle()}
      card = NewSession.account_card(read, nil)

      assert card.state == :required
      refute card.usable?
    end

    test "a login in flight is waiting, and carries the code and the link" do
      read = %{"account" => nil, "requiresOpenaiAuth" => true, "login" => pending()}
      login = %{login_id: "l1", url: "https://auth.openai.com/codex/device", code: "ABCD-1234"}

      card = NewSession.account_card(read, login)

      assert card.state == :waiting
      assert card.code == "ABCD-1234"
      assert card.login_id == "l1"
    end

    test "a pending login the runtime knows about is waiting even with nothing held here" do
      read = %{"account" => nil, "requiresOpenaiAuth" => true, "login" => pending()}
      assert NewSession.account_card(read, nil).state == :waiting
    end

    test "a connected subscription is usable, and names who it is" do
      read = %{
        "account" => %{"type" => "chatgpt", "email" => "a@b.c", "planType" => "pro"},
        "requiresOpenaiAuth" => false,
        "login" => idle()
      }

      card = NewSession.account_card(read, nil)

      assert card.state == :connected
      assert card.usable?
      assert card.identity == "a@b.c"
    end

    test "a runtime that says no auth is required is usable without an identity" do
      read = %{"account" => nil, "requiresOpenaiAuth" => false, "login" => idle()}
      assert NewSession.account_card(read, nil).usable?
    end

    test "only an https URL may be offered as a link" do
      assert NewSession.https?("https://auth.openai.com/codex/device")
      refute NewSession.https?("http://auth.openai.com/codex/device")
      refute NewSession.https?("javascript:alert(1)")
      refute NewSession.https?("https:///no-host")
      refute NewSession.https?(nil)
    end

    test "the gate is the model prefix, not the provider" do
      form = %NewSession{NewSession.new() | model_choice: :custom, model_text: "openai_codex:x"}
      assert NewSession.requires_chatgpt?(form, {:text, nil})

      plain = %NewSession{form | model_text: "openai:gpt-5"}
      refute NewSession.requires_chatgpt?(plain, {:text, nil})
      refute NewSession.requires_chatgpt?(NewSession.new(), {:text, nil})
    end
  end

  defp idle, do: %{"status" => "idle", "loginId" => nil, "flow" => nil, "error" => nil}

  defp pending,
    do: %{"status" => "pending", "loginId" => "l1", "flow" => "device_code", "error" => nil}

  # ------------------------------------------------------------------------------------
  # The page
  # ------------------------------------------------------------------------------------

  describe "the page" do
    setup :endpoint

    test "renders the five controls and the sentence under each of the honest ones",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/new")

      assert html =~ "New session"
      assert html =~ "Provider"
      assert html =~ "Model"
      assert html =~ "Workspace"
      assert html =~ "Thinking"
      assert html =~ "File access"

      # Nothing stated, so nothing sent, and the page says which.
      assert html =~ "Sends no sandbox_mode — the plane decides"
      assert html =~ "Sends no reasoning_effort — the runtime decides"
      assert html =~ "Sends no model option"
    end

    test "offers every provider this node reports, dimming the ones whose probe found none",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/new")

      rows = NewSession.provider_rows(Ouroboros.Gateway.Methods.Present.providers())

      for row <- rows do
        assert html =~ ~s(value="#{row.name}"), "#{row.name} is missing from the picker"
      end

      # Whether anything is dimmed is a property of this machine's PATH, so the assertion
      # is the implication rather than the fact.
      if Enum.any?(rows, &(not &1.detected?)) do
        assert html =~ "ouro-new-dim"
        assert html =~ "Dimmed entries are ones whose probe found no executable."
      end
    end

    test "the model control follows the provider, and the hint follows the control",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      html = change(view, %{"provider" => "native"})

      assert html =~ "Search models…"
      assert html =~ "Runtime default"
      assert html =~ "Custom…"
      assert html =~ "Sends no model option (runtime default)"

      # And the sentence is the one the form's own function produces for its own state.
      assert html =~ intent(view).hint
    end

    test "a search narrows the list here, and never hides the two rows it must not",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "native"})
      wide = NewSession.listed(field(view))

      html = change(view, %{"model_search" => "no-model-is-called-this"})

      assert html =~ "0 models match"
      assert html =~ "Runtime default"
      assert html =~ "Custom…"
      # The catalogue itself did not move; only what is drawn from it did.
      assert NewSession.listed(field(view)) == wide
    end

    test "choosing a model moves the hint, and the request follows it", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "native"})

      # Whatever this build's catalogue actually offers, rather than an id typed here that
      # a snapshot bump could retire.
      assert {:rows, rows, _total} = field(view)
      assert [_default, first | _rest] = rows
      assert {:catalog, id} = first.choice

      html = change(view, %{"model_choice" => NewSession.choice_value(first.choice)})

      assert html =~ "Sends #{id}"

      assert {:ok, params} = start_params(view)
      assert params["model"] == id
    end
  end

  # ------------------------------------------------------------------------------------
  # Sandbox and effort, through the page
  # ------------------------------------------------------------------------------------

  describe "the sandbox cards" do
    setup :endpoint

    test "an untouched picker leaves the key out of the request entirely", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert html =~ "Not stated"
      _ = change(view, %{"provider" => "claude"})

      assert {:ok, params} = start_params(view)
      refute Map.has_key?(params, "sandbox_mode")
    end

    test "a chosen card sends its own word, and the wire keeps `unrestricted`",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "claude"})

      html =
        view
        |> element(~s(button[phx-value-mode="unrestricted"]))
        |> render_click()

      # Every label a person reads says full access; the parameter keeps the schema's word.
      assert html =~ "Full access — no sandbox"
      assert html =~ "Sends sandbox_mode unrestricted"

      assert {:ok, params} = start_params(view)
      assert params["sandbox_mode"] == "unrestricted"
    end

    test "the risky row wears the warning tone whether or not it is chosen", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert html =~ "ouro-card-warn"

      chosen =
        view |> element(~s(button[phx-value-mode="read_only"])) |> render_click()

      # Chosen safe row takes the ordinary selected treatment; the risky row keeps its own.
      assert chosen =~ "ouro-card-on"
      assert chosen =~ "ouro-card-warn"
    end

    test "thinking sends only when chosen", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "claude"})
      assert {:ok, params} = start_params(view)
      refute Map.has_key?(params, "reasoning_effort")

      html = change(view, %{"provider" => "claude", "effort" => "low"})
      assert html =~ "Sends reasoning_effort low"

      assert {:ok, chosen} = start_params(view)
      assert chosen["reasoning_effort"] == "low"
    end
  end

  # ------------------------------------------------------------------------------------
  # Browse
  # ------------------------------------------------------------------------------------

  describe "the browse panel" do
    setup :endpoint
    setup :browse_root

    test "lists the roots this node browses and the directories under one", %{
      conn: conn,
      root: root
    } do
      {:ok, view, _html} = live(conn, "/new")

      html = open_browse(view, root)

      assert html =~ root
      assert html =~ "alpha"
      assert html =~ "beta"
      # Directories only: a plain file under the same directory is not a row.
      refute html =~ "not-a-directory.txt"
    end

    test "walks into a directory and back out through the parent row", %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/new")
      _ = open_browse(view, root)

      inside = browse_to(view, Path.join(root, "alpha"))
      assert inside =~ "alpha-child"

      # The parent row exists because the parent is itself inside a root.
      out =
        view |> element(~s(button[phx-value-path="#{root}"].ouro-browse-open)) |> render_click()

      assert out =~ "beta"
    end

    test "picking a directory writes the workspace input and closes the panel",
         %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/new")
      _ = open_browse(view, root)

      html =
        view
        |> element(~s(button.ouro-browse-use[phx-value-path="#{Path.join(root, "beta")}"]))
        |> render_click()

      assert form(view).workspace == Path.join(root, "beta")
      assert html =~ ~s(value="#{Path.join(root, "beta")}")
      refute html =~ "browse directories"
    end

    test "a listing the method cut says so, with the bound the method itself holds",
         %{conn: conn, root: root} do
      wide = Path.join(root, "wide")
      for n <- 1..(Browse.limit() + 1), do: File.mkdir_p!(Path.join(wide, "d#{n}"))

      {:ok, view, _html} = live(conn, "/new")
      _ = open_browse(view, root)

      html = browse_to(view, wide)

      assert html =~ "#{Browse.limit()} of more shown"
    end

    test "a refusal is rendered in the method's own words, and names where it does look",
         %{conn: conn, root: root} do
      {:ok, view, _html} = live(conn, "/new")
      _ = open_browse(view, root)

      html = browse_to(view, "/etc/ouroboros-does-not-browse-here")

      assert html =~ "params.path is outside every directory this node browses"
      assert html =~ "this node browses:"
      assert html =~ root

      # And the listing the operator was standing in is still there.
      assert html =~ "alpha"
    end
  end

  # ------------------------------------------------------------------------------------
  # Refusal rendering, through the page
  # ------------------------------------------------------------------------------------

  describe "a refused start" do
    setup :endpoint

    test "renders the runtime's own sentence and leaves the form exactly as it was",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      # A provider name this node does not serve. The form only offers real ones, so this
      # is the stale-page case: the runtime is the authority and it says so by name.
      _ =
        change(view, %{
          "provider" => "no-such-provider",
          "workspace" => "/srv/keep-me",
          "effort" => "high"
        })

      html = view |> element("form.ouro-new-form") |> render_submit()

      assert html =~ "params.provider must name a provider this node serves"

      # Nothing was cleared: a refusal is information about the request, and retyping the
      # path would be the page punishing the operator for the runtime's answer.
      assert form(view).workspace == "/srv/keep-me"
      assert form(view).effort == "high"
      assert html =~ ~s(value="/srv/keep-me")
    end

    test "starting with no provider is refused by the form before a call is made",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      html = view |> element("form.ouro-new-form") |> render_submit()

      assert html =~ "choose a provider before starting a session"
    end
  end

  # ------------------------------------------------------------------------------------
  # ChatGPT gating, through the page
  # ------------------------------------------------------------------------------------

  describe "ChatGPT gating" do
    setup :endpoint

    test "an openai_codex model raises the card and disables Start with the reason",
         %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      # Before: no card, and the button is the ordinary one.
      refute html =~ "Connect ChatGPT first"

      html = choose_codex(view)

      assert html =~ "ChatGPT"
      assert html =~ "Required"
      assert html =~ "Connect ChatGPT first"
      assert has_element?(view, "button[type=submit][disabled]")
    end

    test "Connect starts a device-code login and shows the code and the https link",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")
      _ = choose_codex(view)

      html = view |> element(~s(button[phx-click="connect-chatgpt"])) |> render_click()

      assert html =~ "Waiting"
      assert html =~ "ABCD-1234"
      assert html =~ ~s(href="https://auth.openai.com/codex/device")
      assert html =~ "Cancel"
    end

    test "Cancel drops the code and returns the card to what the runtime says",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")
      _ = choose_codex(view)
      _ = view |> element(~s(button[phx-click="connect-chatgpt"])) |> render_click()

      html = view |> element(~s(button[phx-click="cancel-chatgpt"])) |> render_click()

      refute html =~ "ABCD-1234"
      assert html =~ "Required"
    end

    test "a model with no subscription prefix raises no card at all", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "native"})
      _ = change(view, %{"model_choice" => "custom"})
      html = change(view, %{"model_text" => "openai:gpt-5"})

      refute html =~ "Connect ChatGPT first"
      assert html =~ "Sends openai:gpt-5"
    end
  end

  # ------------------------------------------------------------------------------------
  # The deck's half of `?open`
  # ------------------------------------------------------------------------------------

  defmodule FakePlane do
    @moduledoc false
    use GenServer

    def start(opts), do: GenServer.start(__MODULE__, opts)

    @impl true
    def init(opts) do
      id = Keyword.fetch!(opts, :id)
      {:ok, _owner} = Registry.register(Ouroboros.Interactive.Registry, id, nil)
      {:ok, %{id: id, test: Keyword.fetch!(opts, :test), events: Keyword.get(opts, :events, [])}}
    end

    @impl true
    def handle_call(:info, _from, state), do: {:reply, {:ok, session(state)}, state}

    def handle_call({:subscribe, subscriber, cursor}, _from, state) do
      send(state.test, {:subscribed, subscriber, cursor})
      {:reply, {:ok, state.events}, state}
    end

    def handle_call({:unsubscribe, _subscriber}, _from, state), do: {:reply, :ok, state}

    defp session(state) do
      %Ouroboros.Interactive.State{
        id: state.id,
        node: node(),
        provider: :claude_code,
        workspace: "/tmp/w",
        workspace_mode: :shared_read,
        status: :running,
        created_at: "2026-08-29T10:00:00Z",
        updated_at: "2026-08-29T12:00:00Z"
      }
    end
  end

  describe "?open" do
    setup :endpoint

    test "the deck opens the session the form navigated to", %{conn: conn} do
      id = "web-new-#{System.unique_integer([:positive])}"

      {:ok, pid} =
        FakePlane.start(
          id: id,
          test: self(),
          events: [
            %Ouroboros.Interactive.Event{
              id: "e1",
              session_id: id,
              sequence: 1,
              type: :output_text_final,
              timestamp: "2026-08-29T12:00:01Z",
              payload: %{"text" => "opened from the form"},
              turn_id: "t1"
            }
          ]
        )

      on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

      # The path is the form's own, so the two halves cannot be typed differently.
      {:ok, _view, html} = live(conn, NewSession.deck_path(id))

      assert_receive {:subscribed, _subscriber, 0}
      assert html =~ "opened from the form"
      assert html =~ "ouro-transcript"
    end

    test "an unreadable ?open opens nothing rather than guessing", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/?open=not-a-plane:abc")
      assert html =~ "Nothing open"

      {:ok, _view, bare} = live(conn, "/?open=abc")
      assert bare =~ "Nothing open"
    end
  end

  # ------------------------------------------------------------------------------------
  # Read scope
  # ------------------------------------------------------------------------------------

  describe "a read-scope endpoint" do
    setup do: endpoint(%{}, :read)

    test "says why it cannot start or browse, rather than hiding the controls",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/new")

      assert html =~ "OUROBOROS_WEB_SCOPE=read"
      assert html =~ "does not serve"
      assert html =~ "Browse…"
      assert html =~ "Start session"
    end
  end

  # ------------------------------------------------------------------------------------
  # Harness
  # ------------------------------------------------------------------------------------

  defp endpoint(_context, scope \\ :operate)

  defp endpoint(context, scope), do: endpoint_with(context, scope, fn _dir -> :ok end)

  # The same endpoint, with a `web.prefs.json` already in the data directory — the state a
  # second visit to /new is in after a first one started something.
  defp endpoint_seeded(context) do
    endpoint_with(context, :operate, fn dir ->
      Ouroboros.Web.Prefs.write(dir, %{
        "provider" => "native",
        "workspace" => "/srv/remembered",
        "sandbox_mode" => "workspace_write",
        "reasoning_effort" => "high"
      })
    end)
  end

  # And with one that cannot be read at all, which must cost the page nothing.
  defp endpoint_corrupt(context) do
    endpoint_with(context, :operate, fn dir ->
      File.write!(Ouroboros.Web.Prefs.path(dir), "{\"provider\": ")
    end)
  end

  defp endpoint_with(_context, scope, seed) do
    dir = Path.join(System.tmp_dir!(), "ouroboros-web-new-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    seed.(dir)

    config = Config.new!(data_dir: dir, scope: scope)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    conn = get(build_conn(), "/auth?token=#{@token}")

    {:ok, conn: put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value), dir: dir}
  end

  # A rows-field carrying one catalogue model, for the promote tests: the only thing they
  # need from a catalogue is whether it lists a given id.
  defp seeded_field do
    NewSession.model_field(
      catalogue([provider_row(:native, total: 1, models: [model("seeded-model")])]),
      "native"
    )
  end

  # A real directory tree, and a real root for `workspace.browse` to be bounded by, so the
  # panel is driven against the method rather than against a stand-in for it.
  defp browse_root(_context) do
    root = Path.join(System.tmp_dir!(), "ouroboros-browse-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join([root, "alpha", "alpha-child"]))
    File.mkdir_p!(Path.join(root, "beta"))
    File.write!(Path.join(root, "not-a-directory.txt"), "")

    previous = Application.get_env(:ouroboros, :workspace_allowed_roots, [])
    Application.put_env(:ouroboros, :workspace_allowed_roots, [root])

    on_exit(fn ->
      Application.put_env(:ouroboros, :workspace_allowed_roots, previous)
      File.rm_rf(root)
    end)

    # `canonicalize/1` resolves the symlink macOS puts in front of /tmp, and every path the
    # method answers with is canonical — so the fixture has to be named the same way.
    {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(root)
    {:ok, root: canonical}
  end

  defp change(view, params) do
    view |> element("form.ouro-new-form") |> render_change(params)
  end

  defp open_browse(view, path) do
    _ = view |> element(~s(button[phx-click="browse-open"])) |> render_click()
    browse_to(view, path)
  end

  defp browse_to(view, path) do
    render_click(view, "browse-to", %{"path" => path})
  end

  # Three steps, because each one is what puts the next control on the page: the model
  # picker exists only once a provider is chosen, and the text input only once the picker
  # is on its Custom row.
  defp choose_codex(view) do
    _ = change(view, %{"provider" => "native"})
    _ = change(view, %{"model_choice" => "custom"})
    change(view, %{"model_text" => "openai_codex:gpt-5.6-sol"})
  end

  # The form as the operator's own clicks left it. Reached through the view's process state
  # because that *is* the authority here: the whole design of this page is that the socket
  # holds the choice and the request is derived from it, so the assertion has to be made
  # against the socket rather than against a re-derivation of it in the test.
  defp form(view), do: :sys.get_state(view.pid).socket.assigns.form
  defp catalogue_of(view), do: :sys.get_state(view.pid).socket.assigns.catalogue

  defp field(view), do: NewSession.model_field(catalogue_of(view), form(view).provider)
  defp intent(view), do: NewSession.model_intent(form(view), field(view))
  defp start_params(view), do: NewSession.start_params(form(view), field(view))
end
