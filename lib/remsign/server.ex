defmodule Remsign.Server do
  defstruct name: :dummy, dealer_port: 0
  # import Logger, only: [log: 2]

  def canonical_name(kval) do
    String.to_atom(Remsign.Pubkey.keyid(kval))
  end

  def new(kval, cfg = %{}) do
    {dp, _dsock, _dpid} = Remsign.Dealer.alloc(cfg)
    %Remsign.Server{name: canonical_name(kval), dealer_port: dp }
  end
end
