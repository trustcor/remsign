defmodule Remsign.FileReader do
  @moduledoc """
  Reads a text file, split into lines, then patches in any
  #include <filename> lines with the contents of other files,
  then conjoins all of those lines back into a complete
  string. Essentially a C-macro include.
  """
  import Logger, only: [log: 2]

  @doc """
  make the second filename operate from the same base directory
  as the first, unless it is already an absolute pathname
  """
  def relativize(f1, f2) do
    if f2 == Path.absname(f2) do
      f2
    else
      Path.join(Path.dirname(f1), f2)
    end
  end

  defp _substitute_include(fname, l) do
    m = Regex.named_captures(~r/^(?<spaces> *)#include *(?<ifile>.*)$/, l)
    if m == nil do
      l
    else
      ifile = relativize(fname, m["ifile"])
      if fname == ifile do
        # immediately recursive loop - ignore
        log(:warn, "Immediate recursion detected in inclusion - ignoring")
        []
      else
        {state, il} = readlines(ifile)
        if state == :ok do
          Enum.map(il, fn l -> m["spaces"] <> l end)
        else
          # something wrong - maybe no file?
          []
        end
      end
    end
  end

  defp _substitute_includes(fname, lines) do
    List.flatten(Enum.map(lines, fn l -> _substitute_include(fname, l) end))
  end

  def readlines_s(fname, e = {:error, _reason}) do
    log(:warn, "Error on readlines for #{fname}: #{inspect(e)}")
    e
  end
  def readlines_s(fname, {:ok, cont}) do
    x = String.split(cont, "\n")
    if Enum.find(x, fn l -> Regex.match?(~r/^ *#include *(.*)$/, l) end) do
      {:ok, _substitute_includes(fname, x)}
    else
      {:ok, x} # substitution complete
    end
  end

  @doc """
  Read all of the contents of file `fname`, split by newline
  and return {:ok, [lines...]}, or {:error, reason} if this
  can't be done.
  """
  def readlines(fname) do
    r = {state, c} = readlines_s(fname, File.read(fname))
    if state == :ok do
      {:ok, c}
    else
      r
    end
  end

  @doc """
  Read an included file, then join contents into a large string
  """
  def readinclude(fname) do
    r = {state, c} = readlines(fname)
    if state == :ok do
      {:ok, Enum.join(c, "\n")}
    else
      r
    end
  end
end
