defmodule Remsign.Utils do
  def get_in_default(m, kl, d) do
    case get_in(m, kl) do
      nil -> d
      r -> r
    end
  end
end
