-module(mug_ffi).

-export([send/2, recv/3, shutdown/1,
         coerce_tcp_message/1, coerce_tls_message/1,
         active_once/0, passive/0, tls_upgrade/3, tls_connect/5,
         get_certs_keys/1, tls_downgrade/2, get_system_cacerts/0]).

active_once() ->
    once.

passive() ->
    false.

send({tcp_socket, Socket}, Packet) ->
    normalise(gen_tcp:send(Socket, Packet));
send({tls_socket, Socket}, Packet) ->
    normalise(ssl:send(Socket, Packet)).

recv({tcp_socket, Socket}, Length, Timeout) ->
    gen_tcp:recv(Socket, Length, Timeout);
recv({tls_socket, Socket}, Length, Timeout) ->
    ssl:recv(Socket, Length, Timeout).

shutdown({tcp_socket, Socket}) ->
    normalise(gen_tcp:shutdown(Socket, read_write));
shutdown({tls_socket, Socket}) ->
    normalise(ssl:shutdown(Socket, read_write)).

tls_upgrade(Socket, Options, Timeout) ->
    normalise(ssl:connect(Socket, Options, Timeout)).

tls_connect(Host, Port, GenTcpOptions, Options, Timeout) ->
    normalise(ssl:connect(Host, Port, GenTcpOptions ++ Options, Timeout)).

get_certs_keys(CertsKeysList) ->
    lists:map(
      fun (CertsKeys) ->
              case CertsKeys of
                  {der_encoded_certificates_keys, Certs, {der_encoded_key, KeyAlg, KeyBin}} ->
                      #{ cert => lists:map(fun unicode:characters_to_list/1, Certs),
                         key => {normalize_key_algo(KeyAlg), KeyBin} };
                  {pem_encoded_certificates_keys, Certfile, Keyfile, none} ->
                      #{ certfile => unicode:characters_to_list(Certfile),
                         keyfile => unicode:characters_to_list(Keyfile) };
                  {pem_encoded_certificates_keys, Certfile, Keyfile, {some, Password}} ->
                      #{ certfile => unicode:characters_to_list(Certfile),
                         keyfile => unicode:characters_to_list(Keyfile),
                         password => unicode:characters_to_list(Password) }
              end
      end, CertsKeysList).

normalize_key_algo(rsa_private_key) -> 'RSAPrivateKey';
normalize_key_algo(dsa_private_key) -> 'DSAPrivateKey';
normalize_key_algo(ec_private_key) -> 'ECPrivateKey';
normalize_key_algo(private_key_info) -> 'PrivateKeyInfo'.

tls_downgrade(Socket, Timeout) ->
    case ssl:close(Socket, Timeout) of
        ok -> {error, closed};
        {ok, Port} -> {ok, {Port, nil}};
        {ok, Port, Data} -> {ok, {Port, {some, Data}}};
        {error, _} = E -> E
    end.

get_system_cacerts() ->
    try public_key:cacerts_get() of
        Certs -> {ok, Certs}
    catch
        error:{failed_load_certs, Reason} -> {error, Reason}
    end.

normalise(ok) ->
    {ok, nil};
normalise({ok, T}) ->
    {ok, T};
normalise({error, {timeout, _}}) ->
    {error, timeout};
normalise({error, {tls_alert, {Alert, Description}}}) ->
    {error, {tls_alert, Alert, unicode:characters_to_binary(Description)}};
normalise({error, _} = E) ->
    E.

coerce_tcp_message({tcp, Socket, Data}) ->
    {packet, {tcp_socket, Socket}, Data};
coerce_tcp_message({tcp_closed, Socket}) ->
    {socket_closed, {tcp_socket, Socket}};
coerce_tcp_message({tcp_error, Socket, Error}) ->
    {socket_error, {tcp_socket, Socket}, Error}.
%% Only sent in {active, N} mode when counter drops to 0.
%% coerce_tcp_message({tcp_passive, Socket}) ->
%%    {passive, {tcp_socket, Socket}}.

coerce_tls_message({ssl, Socket, Data}) ->
    {packet, {tls_socket, Socket}, Data};
coerce_tls_message({ssl_closed, Socket}) ->
    {socket_closed, {tls_socket, Socket}};
coerce_tls_message({ssl_error, Socket, Error}) ->
    {socket_error, {tls_socket, Socket}, Error}.
%% Only sent in {active, N} mode when counter drops to 0.
%% coerce_tls_message({ssl_passive, Socket}) ->
%%   {passive, {tls_socket, Socket}}.
