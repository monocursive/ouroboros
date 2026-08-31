defmodule Ouroboros.Web.Live.LoadingState do
  @moduledoc """
  A compact, token-only activity indicator for work whose duration is unknown.

  The grid is decorative. The visible label is announced once when the state appears,
  while the elapsed timer is hidden from assistive technology so a ten-hertz clock does
  not become a ten-hertz announcement. `ElapsedTimer` owns that clock in the browser;
  `phx-update="ignore"` keeps a normal LiveView patch from resetting it to zero.

  The three patterns share the same nine cells:

    * `:drive` sends a chevron wavefront to the right;
    * `:dots` is the same wavefront with round cells;
    * `:orbit` runs a single front around the perimeter.

  Reduced-motion behaviour belongs to the stylesheet: the cells and shimmer become
  still, but the elapsed time keeps counting because it conveys information rather than
  decoration.
  """

  use Phoenix.Component

  @drive [90, 180, 270, 0, 90, 180, 90, 180, 270]
  @orbit [0, 110, 220, 770, nil, 330, 660, 550, 440]

  attr :id, :string, required: true
  attr :label, :string, default: "Agent working"
  attr :variant, :any, default: :drive

  def loading(assigns) do
    assigns = assign(assigns, :pattern, pattern(assigns.variant))

    ~H"""
    <div class="ouro-loading-state" role="status" aria-live="polite" aria-atomic="true">
      <span
        class="ouro-loader-grid"
        style={"--ouro-loader-duration: #{@pattern.duration}ms"}
        aria-hidden="true"
      >
        <span
          :for={{delay, index} <- Enum.with_index(@pattern.delays)}
          class={[
            "ouro-loader-cell",
            @pattern.round? && "ouro-loader-cell-round",
            is_integer(delay) && "ouro-loader-cell-active"
          ]}
          style={is_integer(delay) && "--ouro-loader-delay: #{delay}ms"}
          data-cell={index}
        />
      </span>

      <span class="ouro-loading-label">{@label}</span>
      <span
        id={"#{@id}-elapsed"}
        class="ouro-loading-elapsed"
        phx-hook="ElapsedTimer"
        phx-update="ignore"
        aria-hidden="true"
      >0.0s</span>
    </div>
    """
  end

  defp pattern(variant) when variant in [:dots, "dots"],
    do: %{delays: @drive, duration: 650, round?: true}

  defp pattern(variant) when variant in [:orbit, "orbit"],
    do: %{delays: @orbit, duration: 950, round?: false}

  defp pattern(_drive), do: %{delays: @drive, duration: 650, round?: false}
end
