defmodule Endecodes do
  @moduledoc """
  this module is made for encodeing list, tuple, e.t.c value 
  """

  @doc """
  Hello world.

  ## Examples

      iex> Endecodes.mask_code(["32323232", "csfsfsf"], :encode)
      "jcjhsdguevufdqugduikqba8wbkkchav"

  """
  def mask_code(code, :encode) do
    inv_key = "K3EUWY7CLOP2N7FZN5TFVPR2BE"
    key = "QGUaffj5a853MEu6K0w3aGG7qBes89Uz"
    {:ok, iv} =  inv_key |> Base.decode32(padding: false)
    init_state = :crypto.stream_init(:aes_ctr, key, iv)
    {_, encrypted} = :crypto.stream_encrypt(init_state, to_string(code))
    Base.encode32(encrypted, padding: false, case: :lower)
  end

  def mask_code(code, :decode) do
    enc_iv = "K3EUWY7CLOP2N7FZN5TFVPR2BE"
    key = "QGUaffj5a853MEu6K0w3aGG7qBes89Uz"
    decode = Base.decode32(code, padding: false, case: :lower)
    case decode do
      {:ok, ciphertext} ->
        {:ok, iv} = enc_iv |> Base.decode32(padding: false)
        init_state = :crypto.stream_init(:aes_ctr, key, iv)
        {_, decrypted_text} = :crypto.stream_decrypt(init_state, ciphertext)
        if is_binary(decrypted_text), do: String.split(decrypted_text, "::"), else: []
      _ -> []
    end
  end

  def mask_code(code, :decodes) do
    case Base.decode32(code, padding: false, case: :lower) do
      {:ok, ciphertext} ->
        {:ok, iv} = "K3EUWY7CLOP2N7FZN5TFVPR2BE" |> Base.decode32(padding: false)
        key = "QGUaffj5a853MEu6K0w3aGG7qBes89Uz"
        init_state = :crypto.stream_init(:aes_ctr, key, iv)
        {_, decrypted_text} = :crypto.stream_decrypt(init_state, ciphertext)
        if is_binary(decrypted_text), do: String.split(decrypted_text, "::"), else: []
      _ -> []
    end
  end

end
