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
  import ExUnit.CaptureLog

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

  defp native_with_anthropic_key(present, source \\ nil, workspace_configured \\ false) do
    probed(:native, %{
      installed: true,
      compatible: true,
      version: "1.0",
      executable: "in-process",
      details: %{
        "credentials" => [
          %{
            "provider" => "anthropic",
            "env" => "ANTHROPIC_API_KEY",
            "present" => present,
            "source" => source,
            "workspace_env" => "ANTHROPIC_WORKSPACE_ID",
            "workspace_configured" => workspace_configured
          }
        ]
      }
    })
  end

  defp with_xai_key(provider, present, source \\ nil) do
    probed(provider, %{
      installed: true,
      compatible: true,
      version: "1.0",
      executable: "in-process",
      details: %{
        "credentials" => [
          %{
            "provider" => "xai",
            "env" => "XAI_API_KEY",
            "present" => present,
            "source" => source
          }
        ]
      }
    })
  end

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
      reasoning_efforts: Keyword.get(opts, :reasoning_efforts, ["low", "medium", "high"]),
      pricing: nil
    }
  end

  defp before?(text, left, right) do
    {left_at, _length} = :binary.match(text, left)
    {right_at, _length} = :binary.match(text, right)
    left_at < right_at
  end

  # ------------------------------------------------------------------------------------
  # The provider picker
  # ------------------------------------------------------------------------------------

  describe "provider rows" do
    test "a probe that found no executable is annotated for visibility but not availability" do
      rows = NewSession.provider_rows([ready(:claude), missing(:gemini)])

      assert [%{name: "claude", detected?: true, note: nil}, gemini] = rows
      assert gemini.name == "gemini"
      refute gemini.detected?
      assert gemini.note == "no executable found"
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
               "Unavailable providers stay listed so you can see what this computer is missing."
    end

    test "keeps only Anthropic credential presence, never a key value" do
      assert [%{credentials: [credential]}] =
               NewSession.provider_rows([native_with_anthropic_key(true)])

      assert credential == %{
               provider: "anthropic",
               env: "ANTHROPIC_API_KEY",
               present: true,
               source: nil,
               workspace_env: "ANTHROPIC_WORKSPACE_ID",
               workspace_configured?: false
             }
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

    test "rows put Recommended first and Custom last, with readable names and exact ids" do
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
      assert first.label == "Recommended · GPT-5.6 Sol"
      assert first.detail == "Let Ouroboros choose the best model"
      assert sol.label == "GPT-5.6 Sol"
      assert sol.detail == "openai_codex:gpt-5.6-sol · 1.1M context"
      assert bare.label == "bare id"
      assert bare.detail == "bare-id"
      assert last.label == "Custom model…"
    end

    test "groups model rows by provider while preserving each provider's ranking" do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native,
              total: 6,
              models: [
                model("anthropic:claude-opus-5", name: "Claude Opus 5"),
                model("openai_codex:gpt-5.6-sol", name: "GPT-5.6 Sol"),
                model("xai:grok-4.5", name: "Grok 4.5"),
                model("anthropic:claude-sonnet-5", name: "Claude Sonnet 5"),
                model("openai:gpt-5.6", name: "GPT-5.6"),
                model("bare-model", name: "Bare model")
              ]
            )
          ]),
          "native"
        )

      assert {:rows, rows, 6} = field

      assert [anthropic, openai, other, xai] = NewSession.model_groups(rows, "native")
      assert anthropic.label == "Anthropic · direct via Ouroboros (no CLI)"
      assert Enum.map(anthropic.rows, & &1.label) == ["Claude Opus 5", "Claude Sonnet 5"]

      assert openai.label == "OpenAI · direct via Ouroboros (no CLI)"
      assert Enum.map(openai.rows, & &1.label) == ["GPT-5.6 Sol", "GPT-5.6"]

      assert other.label == "Other · direct via Ouroboros (no CLI)"
      assert Enum.map(other.rows, & &1.label) == ["Bare model"]

      assert xai.label == "xAI · direct via Ouroboros (no CLI)"
      assert Enum.map(xai.rows, & &1.label) == ["Grok 4.5"]
    end

    test "a CLI provider groups every model under the CLI that will execute it" do
      assert {:rows, rows, 2} =
               NewSession.model_field(
                 catalogue([
                   provider_row(:claude,
                     total: 2,
                     models: [model("claude-opus-5"), model("claude-sonnet-5")]
                   )
                 ]),
                 "claude"
               )

      assert [%{label: "Claude Code CLI", rows: models}] =
               NewSession.model_groups(rows, "claude")

      assert Enum.map(models, & &1.model) == ["claude-opus-5", "claude-sonnet-5"]
    end

    test "provider routes state direct versus CLI execution in human terms" do
      assert %{
               name: "Ouroboros AI",
               badge: "Direct · no CLI",
               short: "direct model APIs, no CLI"
             } = NewSession.provider_route("native")

      assert %{
               name: "Claude",
               badge: "CLI-backed",
               short: "Claude Code CLI"
             } = NewSession.provider_route("claude")

      assert %{short: "Claude CLI configured for Z.ai", group: "Claude CLI for Z.ai"} =
               NewSession.provider_route("zai")
    end

    test "renders Recommended and Custom around provider optgroups" do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native,
              total: 3,
              models: [
                model("anthropic:claude-sonnet-5", name: "Claude Sonnet 5"),
                model("openai_codex:gpt-5.6-sol", name: "GPT-5.6 Sol"),
                model("xai:grok-4.5", name: "Grok 4.5")
              ]
            )
          ]),
          "native"
        )

      form = %NewSession{NewSession.new() | provider: "native"}

      html =
        render_component(&Ouroboros.Web.Live.NewSessionLive.model_control/1,
          field: field,
          visible: field,
          form: form
        )

      anthropic_group = ~s|<optgroup label="Anthropic · direct via Ouroboros (no CLI)">|
      openai_group = ~s|<optgroup label="OpenAI · direct via Ouroboros (no CLI)">|
      xai_group = ~s|<optgroup label="xAI · direct via Ouroboros (no CLI)">|

      assert html =~ anthropic_group
      assert html =~ openai_group
      assert html =~ xai_group

      assert before?(html, "Recommended", anthropic_group)
      assert before?(html, "Claude Sonnet 5", openai_group)
      assert before?(html, "GPT-5.6 Sol", xai_group)
      assert before?(html, "Grok 4.5", "Custom model…")
    end

    test "a provider with no configured default says so without inventing one" do
      assert {:rows, [first | _rest], 0} =
               NewSession.model_field(catalogue([provider_row(:pi)]), "pi")

      assert first.label == "Recommended"
    end

    test "thinking levels follow the selected model instead of a global three-item list" do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native,
              default: "openai_codex:gpt-5.6-sol",
              total: 2,
              models: [
                model("openai_codex:gpt-5.6-sol",
                  reasoning_efforts: ["none", "low", "medium", "high", "xhigh", "max"]
                ),
                model("openai_codex:gpt-5.4-nano", reasoning_efforts: ["low", "high"])
              ]
            )
          ]),
          "native"
        )

      default = %NewSession{NewSession.new() | provider: "native"}

      assert NewSession.efforts(default, field) == [
               "none",
               "low",
               "medium",
               "high",
               "xhigh",
               "max"
             ]

      nano = %{default | model_choice: {:catalog, "openai_codex:gpt-5.4-nano"}}
      assert NewSession.efforts(nano, field) == ["low", "high"]

      assert {:ok, params} = NewSession.start_params(%{default | effort: "max"}, field)
      assert params["reasoning_effort"] == "max"

      assert {:ok, params} = NewSession.start_params(%{nano | effort: "max"}, field)
      refute Map.has_key?(params, "reasoning_effort")
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
      assert Enum.map(rows, & &1.label) == ["Recommended", "Deep Thinker", "Custom model…"]

      assert {:rows, mini, 3} = NewSession.search(field, "MINI", :runtime_default)
      assert Enum.map(mini, & &1.label) == ["Recommended", "GPT-5.6 Mini", "Custom model…"]
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
        {:unsupported, :runtime_default, "", {nil, "This provider chooses its own model"}},
        {{:text, nil}, :runtime_default, "  my-build  ", {"my-build", "Using my-build"}},
        {{:text, nil}, :runtime_default, "   ",
         {nil, "Ouroboros will choose the recommended model"}},
        {rows, :runtime_default, "", {nil, "Ouroboros will choose the recommended model"}},
        {rows, {:catalog, "openai_codex:x"}, "", {"openai_codex:x", "Using openai_codex:x"}},
        {rows, :custom, " private ", {"private", "Using private"}},
        {rows, :custom, "  ", {nil, "Ouroboros will choose the recommended model"}}
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
      assert intent.hint == "Ouroboros will choose the recommended model"
    end
  end

  # ------------------------------------------------------------------------------------
  # The envelope
  # ------------------------------------------------------------------------------------

  describe "the start envelope" do
    test "an untouched form carries safe file access with the provider" do
      form = %NewSession{NewSession.new() | provider: "claude"}

      assert {:ok, params} = NewSession.start_params(form, {:text, nil})
      assert Map.keys(params) |> Enum.sort() == ["id", "provider", "sandbox_mode"]
      assert params["provider"] == "claude"
      assert params["sandbox_mode"] == "workspace_write"
      assert is_binary(params["id"]) and params["id"] != ""

      refute Map.has_key?(params, "reasoning_effort")
      refute Map.has_key?(params, "model")
      refute Map.has_key?(params, "workspace")
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
    test "a form with no stored values uses safe file access and awaits provider discovery" do
      form = NewSession.new(%{})

      assert form.provider == nil
      assert form.model_choice == :runtime_default
      assert form.workspace == ""
      assert form.sandbox == "workspace_write"
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

      assert NewSession.model_intent(form, {:text, nil}).hint == "Using openai_codex:x"
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

      html =
        view
        |> element("form.ouro-new-form")
        |> render_submit(%{
          "provider" => "no-such-provider",
          "workspace" => "/srv/rejected",
          "effort" => "high"
        })

      assert html =~ "That AI provider is not available on this computer."

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

    test "falls back to safe discovered defaults rather than failing the page", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert html =~ "New session"
      assert form(view).provider == "native"
      assert form(view).workspace == ""
      assert form(view).sandbox == "workspace_write"
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

  describe "the Anthropic API-key card" do
    test "an Anthropic model is required when the Native runtime reports no key" do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native,
              total: 1,
              models: [model("anthropic:claude-sonnet-5")]
            )
          ]),
          "native"
        )

      form = %NewSession{
        NewSession.new()
        | provider: "native",
          model_choice: {:catalog, "anthropic:claude-sonnet-5"}
      }

      rows = NewSession.provider_rows([native_with_anthropic_key(false)])
      card = NewSession.api_key_card(form, field, rows)

      assert card == %{
               provider: "Anthropic",
               key: "anthropic",
               env: "ANTHROPIC_API_KEY",
               managed?: false,
               workspace_env: "ANTHROPIC_WORKSPACE_ID",
               workspace_configured?: false,
               state: :required,
               source: nil,
               usable?: false
             }

      refute NewSession.requires_chatgpt?(form, field)
    end

    test "a present key is usable, and the configured Anthropic default is gated too" do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native,
              default: "anthropic:claude-sonnet-5",
              total: 1,
              models: [model("anthropic:claude-sonnet-5")]
            )
          ]),
          "native"
        )

      form = %NewSession{NewSession.new() | provider: "native"}
      rows = NewSession.provider_rows([native_with_anthropic_key(true, "stored", true)])

      assert %{
               state: :available,
               source: "stored",
               workspace_configured?: true,
               usable?: true
             } =
               NewSession.api_key_card(form, field, rows)

      assert NewSession.api_key_card(form, field, []) == %{
               provider: "Anthropic",
               key: "anthropic",
               env: "ANTHROPIC_API_KEY",
               managed?: false,
               workspace_env: "ANTHROPIC_WORKSPACE_ID",
               workspace_configured?: false,
               state: :checking,
               source: nil,
               usable?: false
             }
    end

    test "other model transports do not raise an Anthropic key requirement" do
      form = %NewSession{
        NewSession.new()
        | provider: "native",
          model_choice: :custom,
          model_text: "openai:gpt-5.6"
      }

      assert NewSession.api_key_card(form, {:text, nil}, []) == nil
    end
  end

  describe "the xAI API-key and Grok subscription cards" do
    test "a direct xAI model requires only its API key" do
      field =
        NewSession.model_field(
          catalogue([
            provider_row(:native, total: 1, models: [model("xai:grok-4.6")])
          ]),
          "native"
        )

      form = %NewSession{
        NewSession.new()
        | provider: "native",
          model_choice: {:catalog, "xai:grok-4.6"}
      }

      card =
        NewSession.api_key_card(
          form,
          field,
          NewSession.provider_rows([with_xai_key(:native, false)])
        )

      assert card == %{
               provider: "xAI",
               key: "xai",
               env: "XAI_API_KEY",
               managed?: false,
               workspace_env: nil,
               workspace_configured?: false,
               state: :required,
               source: nil,
               usable?: false
             }

      refute NewSession.requires_grok?(form)
    end

    test "the managed Grok provider accepts either a subscription or an xAI API key" do
      form = %NewSession{NewSession.new() | provider: "grok"}
      rows = NewSession.provider_rows([with_xai_key(:grok, true, "stored")])

      assert %{managed?: true, key: "xai", state: :available, usable?: true} =
               NewSession.api_key_card(form, :unsupported, rows)

      assert NewSession.requires_grok?(form)

      assert %{state: :required, usable?: false} =
               NewSession.grok_account_card(
                 %{
                   "account" => nil,
                   "requiresGrokAuth" => true,
                   "login" => idle()
                 },
                 nil
               )

      assert %{state: :connected, usable?: true, identity: "subscriber@example.test"} =
               NewSession.grok_account_card(
                 %{
                   "account" => %{
                     "type" => "grok_subscription",
                     "label" => "subscriber@example.test"
                   },
                   "requiresGrokAuth" => false,
                   "login" => idle()
                 },
                 nil
               )
    end

    test "a pending Grok login exposes only its verification link and code" do
      login = %{
        login_id: "grok-device",
        url: "https://auth.x.ai/device?user_code=WXYZ-5678",
        code: "WXYZ-5678"
      }

      assert %{
               state: :waiting,
               usable?: false,
               login_id: "grok-device",
               code: "WXYZ-5678",
               url: "https://auth.x.ai/device?user_code=WXYZ-5678"
             } = NewSession.grok_account_card(nil, login)
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

    test "keeps the primary workflow visible and advanced AI choices disclosed", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert html =~ "New session"
      assert html =~ "Project folder"
      assert html =~ "What should the agent do?"
      assert html =~ "Advanced settings"
      assert html =~ "AI provider"
      assert html =~ "Model"
      assert html =~ "Thinking"
      assert html =~ "File access"
      assert html =~ "The agent can edit files in the project folder."
      assert html =~ "Ouroboros will choose the recommended thinking level."
      refute has_element?(view, "details.ouro-new-advanced[open]")
    end

    test "lists unavailable providers for diagnosis but disables them", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      rows = NewSession.provider_rows(Ouroboros.Gateway.Methods.Present.providers())

      for row <- rows do
        assert html =~ ~s(value="#{row.name}"), "#{row.name} is missing from the picker"

        if not row.detected? do
          assert has_element?(view, ~s(option[value="#{row.name}"][disabled]))
        end
      end

      if Enum.any?(rows, &(not &1.detected?)) do
        assert html =~ "Unavailable providers stay listed"
      end
    end

    test "the model control follows the provider, and the hint follows the control",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      html = change(view, %{"provider" => "native"})

      assert html =~ "Search models…"
      assert html =~ "Recommended"
      assert html =~ "Custom model…"
      assert html =~ "Direct · no CLI"
      assert html =~ "Ouroboros runs this model directly."
      assert html =~ "no model CLI is launched"
      assert html =~ "Anthropic · direct via Ouroboros (no CLI)"
      assert html =~ "Ouroboros will choose the recommended model"

      # And the sentence is the one the form's own function produces for its own state.
      assert html =~ intent(view).hint
    end

    test "provider choices and a CLI model field name the executable path", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert html =~ "Ouroboros AI — direct model APIs, no CLI — recommended"
      assert html =~ "Claude — Claude Code CLI"
      assert html =~ "Grok — Grok Build CLI"
      assert html =~ "Z.ai — Claude CLI configured for Z.ai"

      html = change(view, %{"provider" => "claude"})

      assert html =~ "CLI-backed"
      assert html =~ "Runs through Claude Code CLI."
      assert html =~ "The CLI owns the model session and tools"
      assert html =~ ~s(<optgroup label="Claude Code CLI">)
    end

    test "a search narrows the list here, and never hides the two rows it must not",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "native"})
      wide = NewSession.listed(field(view))

      html = change(view, %{"model_search" => "no-model-is-called-this"})

      assert html =~ "0 models match"
      assert html =~ "Recommended"
      assert html =~ "Custom model…"
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

      assert html =~ "Using #{id}"

      assert {:ok, params} = start_params(view)
      assert params["model"] == id
    end
  end

  # ------------------------------------------------------------------------------------
  # Sandbox and effort, through the page
  # ------------------------------------------------------------------------------------

  describe "the sandbox cards" do
    setup :endpoint

    test "an untouched picker sends the recommended project-only access", %{conn: conn} do
      {:ok, view, html} = live(conn, "/new")

      assert html =~ "Recommended"
      assert html =~ "The agent can edit files in the project folder."
      _ = change(view, %{"provider" => "claude"})

      assert {:ok, params} = start_params(view)
      assert params["sandbox_mode"] == "workspace_write"
    end

    test "a chosen card sends its own word, and the wire keeps `unrestricted`",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => "claude"})

      html =
        view
        |> element(~s(button[phx-value-mode="unrestricted"]))
        |> render_click()

      # Every label a person reads describes file access; the parameter keeps the schema's word.
      assert html =~ "Full computer access"
      assert html =~ "The agent can access files outside the project folder."

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
      assert html =~ "Thinking level: Low"

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

    test "rejects a stale unavailable provider without exposing a runtime validation error",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ =
        change(view, %{
          "provider" => "no-such-provider",
          "workspace" => "/srv/keep-me",
          "effort" => "high"
        })

      html =
        view
        |> element("form.ouro-new-form")
        |> render_submit(%{
          "provider" => "no-such-provider",
          "workspace" => "/srv/keep-me",
          "effort" => "high"
        })

      assert html =~ "That AI provider is not available on this computer."
      refute html =~ "params.provider"

      # Nothing was cleared: a refusal is information about the request, and retyping the
      # path would be the page punishing the operator for the runtime's answer.
      assert form(view).workspace == "/srv/keep-me"
      assert form(view).effort == "high"
      assert html =~ ~s(value="/srv/keep-me")
    end

    test "starting with no provider is refused by the form before a call is made",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")

      _ = change(view, %{"provider" => ""})
      html = view |> element("form.ouro-new-form") |> render_submit()

      assert html =~ "choose an available AI provider before starting"
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
      assert html =~ "Using openai:gpt-5"
    end
  end

  describe "Anthropic API-key gating" do
    setup :endpoint

    setup do
      previous = System.get_env("ANTHROPIC_WORKSPACE_ID")
      System.delete_env("ANTHROPIC_WORKSPACE_ID")
      on_exit(fn -> restore_env("ANTHROPIC_WORKSPACE_ID", previous) end)
      :ok
    end

    test "a Claude model explains the service key and disables Start when it is absent",
         %{conn: conn} do
      previous = System.get_env("ANTHROPIC_API_KEY")
      System.delete_env("ANTHROPIC_API_KEY")
      on_exit(fn -> restore_env("ANTHROPIC_API_KEY", previous) end)

      {:ok, view, _html} = live(conn, "/new")
      html = choose_anthropic(view)

      assert html =~ "Anthropic API"
      assert html =~ "ANTHROPIC_API_KEY"
      assert html =~ "Claude models use direct Anthropic API calls only."
      assert html =~ "subscription login are not used."
      assert html =~ "Add API key"
      assert html =~ "Add Anthropic API key first"
      refute html =~ "Connect ChatGPT first"
      assert has_element?(view, "button[type=submit][disabled]")
    end

    test "a visible service key marks Claude ready without revealing its value", %{conn: conn} do
      previous = System.get_env("ANTHROPIC_API_KEY")
      System.put_env("ANTHROPIC_API_KEY", "test-key-that-must-not-render")
      on_exit(fn -> restore_env("ANTHROPIC_API_KEY", previous) end)

      {:ok, view, _html} = live(conn, "/new")
      html = choose_anthropic(view)

      assert html =~ "Anthropic API"
      assert html =~ "Available"
      assert html =~ "available from the service environment"
      assert html =~ "Its value never reaches this page."
      assert html =~ "ANTHROPIC_WORKSPACE_ID"
      refute html =~ "test-key-that-must-not-render"
      refute html =~ "Manage Anthropic credentials"
      refute has_element?(view, "button[type=submit][disabled]")
    end

    test "an operate link stores a key privately and enables Claude without echoing it",
         %{conn: conn, dir: dir} do
      previous = System.get_env("ANTHROPIC_API_KEY")
      System.delete_env("ANTHROPIC_API_KEY")
      on_exit(fn -> restore_env("ANTHROPIC_API_KEY", previous) end)

      {:ok, view, _html} = live(conn, "/new")
      _ = choose_anthropic(view)

      html =
        view
        |> element(~s(button[phx-click="open-anthropic-key"]))
        |> render_click()

      assert html =~ "Anthropic credentials"
      assert has_element?(view, "#anthropic-key-form input[type=password]")
      assert has_element?(view, "#anthropic-key-form #anthropic-workspace-id")

      secret = "sk-ant-ui-value-must-never-render"

      logs =
        capture_log([level: :debug], fn ->
          view
          |> form("#anthropic-key-form", %{"anthropic_api_key" => secret})
          |> render_submit()
        end)

      html = render(view)
      path = Path.join(dir, "anthropic.key")

      assert %{"api_key" => ^secret, "workspace_id" => nil} =
               Jason.decode!(File.read!(path))

      assert {:ok, stat} = File.lstat(path)
      assert stat.type == :regular
      assert Bitwise.band(stat.mode, 0o777) == 0o600
      assert html =~ "A private Anthropic API key is stored by Ouroboros."
      assert html =~ "Identity-linked keys also need"
      assert html =~ "Manage Anthropic credentials"
      refute html =~ secret
      refute logs =~ secret
      assert logs =~ "[FILTERED]"
      refute has_element?(view, "button[type=submit][disabled]")

      _ =
        view
        |> element(~s(button[phx-click="open-anthropic-key"]))
        |> render_click()

      refute has_element?(view, "#anthropic-api-key[required]")

      html =
        view
        |> form("#anthropic-key-form", %{
          "anthropic_workspace_id" => "wrkspc_Web123"
        })
        |> render_submit()

      assert %{
               "api_key" => ^secret,
               "workspace_id" => "wrkspc_Web123"
             } = Jason.decode!(File.read!(path))

      assert html =~ "A workspace ID is configured"
      refute html =~ secret
    end
  end

  describe "xAI API-key gating" do
    setup :endpoint

    setup do
      previous = System.get_env("XAI_API_KEY")
      System.delete_env("XAI_API_KEY")
      on_exit(fn -> restore_env("XAI_API_KEY", previous) end)
      :ok
    end

    test "a direct Grok model explains xAI billing and disables Start without a key",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")
      html = choose_xai(view)

      assert html =~ "xAI API"
      assert html =~ "XAI_API_KEY"
      assert html =~ "Direct Grok models use the xAI API."
      assert html =~ "SpaceXAI subscription"
      assert html =~ "managed Grok provider"
      assert html =~ "Add xAI API key first"
      assert has_element?(view, "button[type=submit][disabled]")
    end

    test "an operate link stores an xAI key privately and enables the direct model",
         %{conn: conn, dir: dir} do
      {:ok, view, _html} = live(conn, "/new")
      _ = choose_xai(view)

      html = view |> element(~s(button[phx-click="open-xai-key"])) |> render_click()
      assert html =~ "xAI API key"
      assert has_element?(view, "#xai-key-form input[type=password]")

      secret = "xai-ui-value-must-never-render"

      logs =
        capture_log([level: :debug], fn ->
          view
          |> form("#xai-key-form", %{"xai_api_key" => secret})
          |> render_submit()
        end)

      html = render(view)
      path = Path.join(dir, "xai.key")

      assert File.read!(path) == secret
      assert {:ok, stat} = File.lstat(path)
      assert stat.type == :regular
      assert Bitwise.band(stat.mode, 0o777) == 0o600
      assert html =~ "A private xAI API key is stored by Ouroboros."
      refute html =~ secret
      refute logs =~ secret
      assert logs =~ "[FILTERED]"
      refute has_element?(view, "button[type=submit][disabled]")
    end
  end

  describe "Grok subscription gating" do
    setup :endpoint

    setup do
      previous = System.get_env("XAI_API_KEY")
      System.delete_env("XAI_API_KEY")
      on_exit(fn -> restore_env("XAI_API_KEY", previous) end)
      :ok
    end

    test "the managed provider offers subscription login or a separately billed API key",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")
      html = change(view, %{"provider" => "grok"})

      assert html =~ "SpaceXAI subscription"
      assert html =~ "Connect an eligible SpaceXAI subscription"
      assert html =~ "API usage is billed separately from a subscription"
      assert html =~ "Connect Grok or add API key first"
      assert has_element?(view, ~s(button[phx-click="connect-grok"]))
      assert has_element?(view, ~s(button[phx-click="open-xai-key"]))
      assert has_element?(view, "button[type=submit][disabled]")
    end

    test "Connect and Cancel use the bounded Grok device flow", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/new")
      _ = change(view, %{"provider" => "grok"})

      html = view |> element(~s(button[phx-click="connect-grok"])) |> render_click()

      assert html =~ "Waiting"
      assert html =~ "WXYZ-5678"
      assert html =~ ~s(href="https://auth.x.ai/device?user_code=WXYZ-5678")
      refute html =~ "cli-secret"

      html = view |> element(~s(button[phx-click="cancel-grok"])) |> render_click()

      refute html =~ "WXYZ-5678"
      assert html =~ "One option required"
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

    test "the deck path percent-encodes a caller-owned id as one segment" do
      assert NewSession.deck_path("a/b?c#d%e") == "/s/interactive/a%2Fb%3Fc%23d%25e"
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

      assert html =~ "This link is view-only."
      assert html =~ "Ask the person who set up Ouroboros"
      assert html =~ "Browse…"
      assert html =~ "Start session"
    end

    test "shows that a missing Anthropic key needs an operate link without offering a write",
         %{conn: conn} do
      previous = System.get_env("ANTHROPIC_API_KEY")
      System.delete_env("ANTHROPIC_API_KEY")
      on_exit(fn -> restore_env("ANTHROPIC_API_KEY", previous) end)

      {:ok, view, _html} = live(conn, "/new")
      html = choose_anthropic(view)

      assert html =~ "This link is view-only, so it cannot store provider credentials."
      refute has_element?(view, ~s(button[phx-click="open-anthropic-key"]))
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
    previous_anthropic_key_file = Application.get_env(:ouroboros, :anthropic_api_key_file)
    previous_xai_key_file = Application.get_env(:ouroboros, :xai_api_key_file)
    Application.put_env(:ouroboros, :anthropic_api_key_file, Path.join(dir, "anthropic.key"))
    Application.put_env(:ouroboros, :xai_api_key_file, Path.join(dir, "xai.key"))
    Ouroboros.Test.GrokAccountAdapter.reset()
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)

    on_exit(fn ->
      if previous_anthropic_key_file,
        do:
          Application.put_env(
            :ouroboros,
            :anthropic_api_key_file,
            previous_anthropic_key_file
          ),
        else: Application.delete_env(:ouroboros, :anthropic_api_key_file)

      if previous_xai_key_file,
        do: Application.put_env(:ouroboros, :xai_api_key_file, previous_xai_key_file),
        else: Application.delete_env(:ouroboros, :xai_api_key_file)

      Ouroboros.Test.GrokAccountAdapter.reset()

      File.rm_rf(dir)
    end)

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

  defp choose_anthropic(view) do
    _ = change(view, %{"provider" => "native"})

    {:rows, rows, _total} = field(view)

    choice =
      Enum.find(rows, fn
        %{choice: {:catalog, "anthropic:" <> _}} -> true
        _other -> false
      end)

    change(view, %{"model_choice" => NewSession.choice_value(choice.choice)})
  end

  defp choose_xai(view) do
    _ = change(view, %{"provider" => "native"})
    _ = change(view, %{"model_choice" => "custom"})
    change(view, %{"model_text" => "xai:grok-4.6"})
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)

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
