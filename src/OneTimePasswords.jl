"""
    module OneTimePasswords

A minimal, fast Julia module for generating and verifying
counter-based (HOTP, RFC 4226), time-based (TOTP, RFC 6238), and
challenge-response (OCRA, RFC 6287) one-time passwords.

Implements RFCs 4226, 6238, and 6287. Compliance not guaranteed. Not audited.

Also provides provisioning URIs and QR-codes for authenticator apps.

!!! warning
    **Security Considerations:**  
    This module implements only the algorithmic core of HOTP, TOTP, and OCRA.  
    It is stateless and does not include rate limiting, lockout, replay 
    tracking, throttling, or secure memory handling.

    Applications using this module must enforce their own controls:
    - Retry and lockout policies  
    - Delays or backoff to slow brute-force  
    - Replay prevention within sessions or windows  
    - Secure storage of shared secrets  
    - Secure transport (e.g., TLS)

    Secrets are Base32‑encoded immutable `String`s. They cannot be zeroized.  
    Use `Vector{UInt8}` and `fill!()` if explicit key erasure is required.

# Timing and Side‑Channel Notes
- OTP code comparisons are constant‑time.  
- Base32 decoding and HMAC operations are not guaranteed constant‑time.  
- For multi‑tenant or hostile environments, use a hardened crypto library or 
  HSM.

# Examples
```jldoctest
julia> using OneTimePasswords

julia> secret = generate_secret();

julia> code = generate(HOTP(), secret, 0; digits=6);

julia> verify(HOTP(), secret, 0, code)
true

julia> account = "alice@example.com";

julia> issuer  = "MyApp";

julia> urilink = uri(HOTP(), secret, account, issuer;
               digits=6, counter=0, algorithm=:SHA1);

julia> svg = qrcode(urilink; format=:svg, size=200, border=2);

julia> tmp_svg = tempname() * "hotp.svg";

julia> open(tmp_svg,"w") do io
           write(io, svg)
       end;

julia> tmp_png = tempname() * "hotp.png";

julia> pngfile = qrcode(urilink; format="png", path=tmp_png);

julia> isfile(pngfile)
true

julia> # qrcode(urilink; format=:ascii, border=1) # Print in the REPL
```

```jldoctest
julia> using OneTimePasswords, Dates

julia> secret = generate_secret();

julia> code = generate(TOTP(), secret; period=Second(30), digits=6);

julia> verify(TOTP(), secret, code; allowed_drift=Second(30))
true

julia> account = "alice@example.com";

julia> issuer  = "MyApp";

julia> urilink = uri(TOTP(), secret, account, issuer; digits=6, 
       period=Second(30));

julia> svg = qrcode(urilink; format=:svg, size=200, border=2);

julia> tmp_svg = tempname() * ".svg";

julia> open(tmp_svg, "w") do io
           write(io, svg)
       end;

julia> tmp_png = tempname() * ".png";

julia> pngfile = qrcode(urilink; format="png", path=tmp_png);

julia> isfile(pngfile)
true

julia> # qrcode(urilink; format=:ascii, border=1) # Print in the REPL
```

```jldoctest
julia> using OneTimePasswords, Dates

julia> secret = generate_secret(64);

julia> suite = "OCRA-1:HOTP-SHA512-8:QA10-T1M";

julia> dt = DateTime(2020,1,1,0,0,30)
2020-01-01T00:00:30

julia> code = generate(OCRA(), secret;
                          suite=suite,
                          challenge="SIG1400000",
                          timestamp=dt,
                          digits=8,
                          algorithm=:SHA512);

julia> verify(OCRA(), secret, code;
               suite=suite,
               challenge="SIG1400000",
               timestamp=dt + Second(60),
               allowed_drift=Second(60),
               digits=8,
               algorithm=:SHA512)
true

julia> account = "alice@example.com";

julia> issuer  = "MyApp";

julia> urilink = uri(OCRA(), secret, "bob", "MyApp";
            suite=suite,
            challenge="SIG1400000",
            timestamp=dt);

julia> svg = qrcode(urilink; format=:svg, size=200, border=2);

julia> tmp_svg = tempname() * ".svg";

julia> open(tmp_svg, "w") do io
           write(io, svg)
       end;

julia> tmp_png = tempname() * ".png";

julia> pngfile = qrcode(urilink; format="png", path=tmp_png);

julia> isfile(pngfile)
true

julia> # qrcode(urilink; format=:ascii, border=1) # Print in the REPL
```

See also [`generate_secret`](@ref), [`AbstractOTP`](@ref), [`HOTP`](@ref), 
[`TOTP`](@ref), [`OCRA`](@ref),  [`generate`](@ref), [`verify`](@ref) 
[`uri`](@ref) and [`qrcode`](@ref).
"""
module OneTimePasswords

using Dates, SHA, Random, CodecBase, QRCoders
using HTTP.URIs: escapeuri

export generate_secret_raw, generate_secret, AbstractOTP, HOTP, TOTP, OCRA
export generate, verify, uri, qrcode

"""
    base32encode(bytes::Vector{UInt8})::String

Encode a byte vector to a Base32 string according to 
[RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648).
Result is always ASCII, using uppercase A-Z and digits 2-7, with `=` padding.

See also [`base32decode`](@ref).
"""
base32encode(bytes::Vector{UInt8}) = String(transcode(Base32Encoder, bytes))

"""
    base32decode(str::AbstractString)::Vector{UInt8}

Decode a Base32 string (per RFC 4648) into a vector of bytes.
The input string is *not* case sensitive and may contain whitespace or 
padding (`=`).
Throws an exception on invalid characters or impossible encoding.

See also [`base32encode`](@ref).
"""
base32decode(str::AbstractString) = transcode(Base32Decoder, Vector{UInt8}(str))

"""
    _hmac(algorithm::Symbol, key::Vector{UInt8}, 
        msg::Vector{UInt8})::Vector{UInt8}

Compute the HMAC of msg using key and the selected algorithm.
Supported algorithms are :SHA1, :SHA256, and :SHA512.
"""
function _hmac(algorithm::Symbol, key::Vector{UInt8}, msg::Vector{UInt8})
    if algorithm === :SHA1
        return SHA.hmac_sha1(key, msg)
    elseif algorithm === :SHA256
        return SHA.hmac_sha256(key, msg)
    elseif algorithm === :SHA512
        return SHA.hmac_sha512(key, msg)
    else
        error("Unknown algorithm $algorithm")
    end
end

"""
    generate_secret_raw(n::Integer=20) -> Vector{UInt8}

Generate `n` cryptographically secure random bytes (OS RNG).
Throws ArgumentError for non-positive or too-large `n`.

# Examples
```jldoctest
julia> using OneTimePasswords, Random

julia> secret_raw = generate_secret_raw();

julia> rand!(RandomDevice(), secret_raw);
```

See also [`generate_secret`](@ref).
"""
function generate_secret_raw(n::Integer=20)
    n <= 0 && throw(ArgumentError("secret length must be positive (got $n)"))
    n > typemax(Int) && throw(ArgumentError("secret length too large"))
    rng = RandomDevice()
    return rand(rng, UInt8, Int(n))
end

"""
    generate_secret([length::Int=20])::String

Generate a cryptographically-strong random secret (byte length `length`)
and return it Base32-encoded.  Default is 20 bytes (good for SHA1/TOTP).

# Examples
```jldoctest
julia> using OneTimePasswords

julia> secret = generate_secret();
```
See also [`base32encode`](@ref), [`base32decode`](@ref) and  and 
[`generate_secret_raw`](@ref).
"""
function generate_secret(n::Integer=20)
    raw = generate_secret_raw(n)
    return base32encode(raw)
end

"""
    AbstractOTP

Abstract supertype for one-time-password generators.
"""
abstract type AbstractOTP end

"""
    HOTP()

Counter-based OTP (RFC 4226).
"""
struct HOTP <: AbstractOTP end

"""
    TOTP()

Time-based OTP (RFC 6238).
"""
struct TOTP <: AbstractOTP end

"""
    OCRA()

The OATH Challenge-Response Algorithm (RFC 6287).
"""
struct OCRA <: AbstractOTP end

"""
    generate(::HOTP, secret::Union{AbstractString,Vector{UInt8}}, 
        counter::Integer; digits::Int=6, algorithm::Symbol=:SHA1)::String

Compute HOTP for `secret` and `counter` (RFC 4226).

# Arguments
- `secret`: may be either a Base32‐encoded `String`, 
   or the raw key bytes as `Vector{UInt8}`.
- `counter`: counter value (Integer).
- `digits`: code length (default 6).
- `algorithm`: `:SHA1`, `:SHA256`, or `:SHA512`.

# Examples
```jldoctest
julia> using OneTimePasswords

julia> # Base32-encoded String secret

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; #  generate_secret()

julia> generate(HOTP(), secret, 0)
"429658"
```

```jldoctest
julia> using OneTimePasswords, Random

julia> # secret as `Vector{UInt8}; generate_secret_raw()

julia> secret_raw = UInt8[0x67, 0xc0, 0x1e, 0xd3, 0x83, 0xa0, 0x9a, 0x8e, 
       0x1a, 0x74, 0x60, 0x58, 0x1e, 0x40, 0x3b, 0x5a, 0xfd, 0x14, 0x19, 0xc5];

julia> generate(HOTP(), secret_raw, 0)
"429658"

julia> rand!(RandomDevice(), secret_raw);
```

See also [`verify(::HOTP)`](@ref).
"""
function generate(::HOTP, secret::Vector{UInt8}, counter::Integer;
    digits::Int=6, algorithm::Symbol=:SHA1)
    digits = _check_digits(digits)
    key = _check_secret_length(algorithm, secret)
    msg = zeros(UInt8, 8)
    for i in 1:8
        msg[9-i] = (counter >> (8 * (i - 1))) & 0xff
    end
    h = _hmac(algorithm, key, msg)
    off = h[end] & 0x0f
    code = (UInt32(h[off+1] & 0x7f) << 24) |
           (UInt32(h[off+2]) << 16) |
           (UInt32(h[off+3]) << 8) |
           UInt32(h[off+4])
    lpad(string(code % UInt32(10^digits)), digits, '0')
end

function generate(::HOTP, secret::AbstractString, counter::Integer; kwargs...)
    generate(HOTP(), base32decode(secret), counter; kwargs...)
end

"""
    generate(::TOTP, secret::Union{AbstractString,Vector{UInt8}};
             time=nothing, period::Union{Period,Integer}=Second(30), 
             digits::Int=6, algorithm::Symbol=:SHA1)::String

Compute a TOTP value for `secret` at the specified `time`
(RFC 6238), with integer step-countging.

!!! warning
    TOTP (RFC 6238) always uses **UTC** epoch seconds (since Jan 1, 1970 UTC).  
    If you pass a `DateTime` without a timezone, it is assumed to be **UTC**.  
    To avoid mismatches, use `Dates.now(UTC)` or an explicit Unix timestamp.

# Examples

```jldoctest
julia> using OneTimePasswords, Dates

julia> # Base32-encoded String secret

julia> secret = "CX6NTW67L7XI3RX7CFUNV4I2Z\
                     SXDVSGPLG4KDZ57IJLTM4SOUPNA===="; # generate_secret(32)

julia> generate(TOTP(), secret; digits=8);

julia> dt = DateTime(2020,1,1,0,0,30);

julia> generate(TOTP(), secret; time=dt, digits=7, period=Second(30), 
           algorithm=:SHA256)
"6413619"
```

```jldoctest
julia> using OneTimePasswords, Dates, Random

julia> # secret as `Vector{UInt8}; generate_secret_raw(32)

julia> secret_raw = UInt8[0x15, 0xfc, 0xd9, 0xdb, 0xdf, 0x5f, 0xee, 0x8d, 0xc6, 
       0xff, 0x11, 0x68, 0xda, 0xf1, 0x1a, 0xcc, 0xae, 0x3a, 0xc8, 0xcf, 0x59, 
       0xb8, 0xa1, 0xe7, 0xbf, 0x42, 0x57, 0x36, 0x72, 0x4e, 0xa3, 0xda];

julia> generate(TOTP(), secret_raw; digits=8);

julia> dt = DateTime(2020,1,1,0,0,30);

julia> generate(TOTP(), secret_raw; time=dt, digits=7, period=Second(30), 
           algorithm=:SHA256)
"6413619"

julia> rand!(RandomDevice(), secret_raw);
```

See also [`verify(::TOTP)`](@ref).
"""
function generate(::TOTP, secret::Vector{UInt8};
    time=nothing, period::Union{Period,Integer}=Second(30),
    digits::Int=6, algorithm::Symbol=:SHA1)
    t = time === nothing ? Dates.now(UTC) : time
    secs = floor(Int, Dates.datetime2unix(t))
    period_int = period isa Period ? Second(period).value : period
    counter = div(secs, period_int)
    generate(HOTP(), secret, counter; digits=digits, algorithm=algorithm)
end

function generate(::TOTP, secret::AbstractString; kwargs...)
    generate(TOTP(), base32decode(secret); kwargs...)
end

"""
    _build_ocra_message(
        suite::AbstractString,
        counter::Union{Nothing,Int}=nothing,
        challenge::AbstractString="",
        passwordhash::AbstractString="",
        session_info::AbstractString="",
        timestamp::Union{Nothing,Int}=nothing)::Vector{UInt8}

Construct the binary “DataInput” value for OCRA (RFC 6287).

The overall layout is:

  DataInput = UTF8(suite) ‖ 0x00 ‖ [ C ] ‖ [ Q ] ‖ [ P ] ‖ [ S ] ‖ [ T ]

where
  - Suite: UTF-8 bytes of the suite string, then a 0x00 separator.
  - C: 8-byte big-endian counter (if suite contains “C”).
  - Q: challenge field (numeric/hex/alpha, padded per Qxxx) (if “Q”).
  - P: password-hash left-padded to the HMAC output length (if PSHAx).  
  - S: session_info UTF-8 right-padded to Snnn bytes (if Snnn).
  - T: 8-byte big-endian timestamp (if suite contains “T”).
"""
function _build_ocra_message(
    suite::AbstractString,
    counter::Union{Nothing,Int}=nothing,
    challenge::AbstractString="",
    passwordhash::AbstractString="",
    session_info::AbstractString="",
    timestamp::Union{Nothing,Int}=nothing)::Vector{UInt8}
    DataInput = split(suite, ":")[3]
    msg = UInt8[]
    append!(msg, codeunits(suite))
    push!(msg, 0x00)
    if occursin(r"(^|-)C", DataInput)
        c = coalesce(counter, 0)
        append!(msg, reinterpret(UInt8, [hton(UInt64(c))]))
    end
    if occursin(r"(^|-)Q", DataInput)
        m = match(r"Q([ANH])(\d+)", DataInput)
        m === nothing && error("Invalid OCRA suite: unsupported 
        or malformed Q field")
        typ, maxch = m.captures
        maxch = parse(Int, maxch)
        if maxch < 4 || maxch > 64
            error("OCRA challenge field Q must have a length between 4 
            and 64 (got $maxch)")
        end
        if typ == "N"
            hexstr = uppercase(string(parse(BigInt, challenge), base=16))
            hexstr = rpad(hexstr, 256, '0')
            qb = hex2bytes(hexstr)
        elseif typ == "H"
            hexstr = uppercase(challenge)
            hexstr = rpad(hexstr, 256, '0')
            qb = hex2bytes(hexstr)
        else
            qb0 = codeunits(challenge)
            length(qb0) > 128 && error("OCRA challenge too long 
            (max 128 bytes)")
            qb = vcat(qb0, zeros(UInt8, 128 - length(qb0)))
        end
        append!(msg, qb)
    end
    for (tag, len) in (("PSHA1", 20), ("PSHA256", 32), ("PSHA512", 64))
        if occursin(tag, DataInput)
            hb = hex2bytes(passwordhash)
            if length(hb) > len
                error("Password hash is longer than allowed for suite ($tag)")

            end
            prepend = zeros(UInt8, len - length(hb))
            append!(msg, prepend)
            append!(msg, hb)
            break
        end
    end
    for (tag, len) in (("S064", 64), ("S128", 128), ("S256", 256),
        ("S512", 512))
        if occursin(tag, DataInput)
            sb = codeunits(session_info)
            if length(sb) > len
                error("Sessioninfo too long: $(length(sb)) > $len")
            end
            append!(msg, sb)
            append!(msg, zeros(UInt8, len - length(sb)))
            break
        end
    end
    if occursin(r"(^|-)T", DataInput)
        t = coalesce(timestamp, 0)
        append!(msg, reinterpret(UInt8, [hton(UInt64(t))]))
    end
    return msg
end

"""
    _dynamic_truncate(h::Vector{UInt8}, digits::Int)::String

Perform dynamic truncation (as in HOTP) on the HMAC result h and return
the OTP as a zero-padded string of length digits.
"""
function _dynamic_truncate(h::Vector{UInt8}, digits::Int)
    off = h[end] & 0x0f
    code_val = (UInt32(h[off+1] & 0x7f) << 24) |
               (UInt32(h[off+2]) << 16) |
               (UInt32(h[off+3]) << 8) |
               UInt32(h[off+4])
    otp = code_val % UInt32(10^digits)
    return lpad(string(otp), digits, '0')
end

"""
    generate(::OCRA, secret::Union{AbstractString,Vector{UInt8}};
             suite::AbstractString = "OCRA-1:HOTP-SHA1-6:QN08",
             counter::Union{Nothing, Integer}=nothing,
             challenge::AbstractString="",
             password::AbstractString="",
             session_info::AbstractString="",
             timestamp::Union{Nothing,Integer}=nothing,
             digits::Int=6,
             algorithm::Symbol=:SHA1)::String

Compute an OCRA one-time password (OTP) according to RFC 6287.

Arguments:
  - `secret`: Base32-encoded shared secret 
     or the raw key bytes as `Vector{UInt8}`.
  - `suite`: OCRA suite definition string.
  - `counter`: Optional counter value. If omitted, 8 zero bytes are used.
  - `challenge`: The challenge/question string (e.g. numeric or hex).
  - `password`: Optional password (P) field.
  - `session_info`: Optional session information (S) field.
  - `timestamp`: Optional timestamp (T) as an integer (e.g. Unix time).  
  - `digits`: The number of digits in the OTP.
  - `algorithm`: The hash algorithm to use (:SHA1, :SHA256, or :SHA512).

# Examples
```jldoctest
julia> using OneTimePasswords, Dates

julia> # Base32-encoded String secret

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> code = generate(OCRA(), secret; suite="OCRA-1:HOTP-SHA1-6:QN08",
            challenge="12345678")
"262022"
```

```jldoctest
julia> using OneTimePasswords, Dates, Random

julia> # secret as `Vector{UInt8}; generate_secret_raw()

julia> secret_raw = UInt8[0x67, 0xc0, 0x1e, 0xd3, 0x83, 0xa0, 0x9a, 0x8e, 
       0x1a, 0x74, 0x60, 0x58, 0x1e, 0x40, 0x3b, 0x5a, 0xfd, 0x14, 0x19, 0xc5];

julia> code = generate(OCRA(), secret_raw; suite="OCRA-1:HOTP-SHA1-6:QN08",
            challenge="12345678")
"262022"

julia> rand!(RandomDevice(), secret_raw);
```

```jldoctest
julia> using OneTimePasswords, Dates

julia> secret = "T6AZ35HKKGWJEUACAUG5MK7T3CBZ5M76Q2GHLMHYOXQEHXKKTATGVH73\
                     QBRRW4MBP4P6QKCVMIMMIIBYEY534KZ\
                     QB6YVK2TE3II3XZA="; # generate_secret(63)

julia> suite = "OCRA-1:HOTP-SHA512-8:QA10-T1M";

julia> dt = DateTime(2020,1,1,0,0,30);

julia> generate(OCRA(), secret;
                 suite=suite,
                 challenge="SIG1400000",
                 timestamp=dt,
                 digits=8,
                 algorithm=:SHA512)
"37236432"
```
See also [`verify(::OCRA)`](@ref).
"""
function generate(::OCRA, secret::Vector{UInt8};
    suite::AbstractString="OCRA-1:HOTP-SHA1-6:QN08",
    counter::Union{Nothing,Integer}=nothing,
    challenge::AbstractString="",
    password::AbstractString="",
    session_info::AbstractString="",
    timestamp::Union{Nothing,Integer,DateTime}=nothing,
    digits::Int=6,
    algorithm::Symbol=:SHA1)
    digits = _check_digits(digits)
    ts = if timestamp isa DateTime
        floor(Int, datetime2unix(timestamp))
    else
        timestamp
    end
    key = _check_secret_length(algorithm, secret)
    msg = _build_ocra_message(suite, counter, challenge,
        password, session_info, ts)
    h = _hmac(algorithm, key, msg)
    return _dynamic_truncate(h, digits)
end

function generate(::OCRA, secret::AbstractString; kwargs...)
    generate(OCRA(), base32decode(secret); kwargs...)
end

"""
    verify(::HOTP, secret::Union{AbstractString,Vector{UInt8}}, 
           counter::Integer, code::AbstractString; digits::Int=6,
           algorithm::Symbol=:SHA1)::Bool

Return `true` if `code` matches the HOTP for `secret` and `counter`.

Arguments are the same as for `generate(::HOTP)`.  `code` is compared in
constant time to mitigate timing attacks.

!!! warning
    **Counter replay**: HOTP (RFC 4226) requires that each counter 
    value MUST be used at most once. This library does not manage 
    counters; it only checks whether a single code matches. Your 
    application/server must track and advance the counter and 
    reject any reused codes to prevent replay attacks.

# Examples
```jldoctest
julia> using OneTimePasswords

julia> # Base32-encoded String secret

julia> secret = generate_secret();

julia> code = generate(HOTP(), secret, 123; digits=6);

julia> verify(HOTP(), secret, 123, code)
true

```jldoctest
julia> using OneTimePasswords, Random

julia> # secret as `Vector{UInt8}; generate_secret_raw()

julia> secret_raw = generate_secret_raw();

julia> code2 = generate(HOTP(), secret_raw, 123);

julia> verify(HOTP(), secret_raw, 123, code2)
true

julia> rand!(RandomDevice(), secret_raw);
```

See also [`generate(::HOTP)`](@ref).
"""
verify(::HOTP, secret::Vector{UInt8}, counter::Integer,
    code::AbstractString; digits::Int=6,
    algorithm::Symbol=:SHA1) =
    _consttime_eq(generate(HOTP(), secret, counter; digits=digits,
            algorithm=algorithm), code)

function verify(::HOTP, secret::AbstractString, counter::Integer,
    code::AbstractString; kwargs...)
    verify(HOTP(), base32decode(secret), counter, code; kwargs...)
end

"""
    verify(::TOTP, secret, code::AbstractString;
           period::Period=Second(30), allowed_drift::Period=Second(30),
           digits::Int=6, time=nothing,
           algorithm::Symbol=:SHA1)::Bool

Return `true` if `code` is a valid TOTP for `secret` at `time`, allowing
±`allowed_drift` time window.

!!! warning
    TOTP (RFC 6238) always uses **UTC** epoch seconds (since Jan 1, 1970 UTC).  
    If you pass a `DateTime` without a timezone, it is assumed to be **UTC**.  
    To avoid mismatches, use `Dates.now(UTC)` or an explicit Unix timestamp.

!!! warning
    **Allowed drift window**: By default, verification allows ±30 seconds 
    (one time-step) of drift. Increasing this `allowed_drift` widens the 
    acceptance window and makes brute forcing easier. For best security,
    keep the drift window as small as your deployment can tolerate.

# Examples
```jldoctest
julia> using OneTimePasswords, Dates

julia> # Base32-encoded String secret

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> dt = DateTime(2022,1,1,0,0,30);

julia> code = generate(TOTP(), secret; time=dt, digits=8);

julia> verify(TOTP(), secret, code; time=dt, digits=8)
true

julia> verify(TOTP(), secret, code; time=dt+Minute(1), digits=8,
                           allowed_drift=Second(60))
true

julia> verify(TOTP(), secret, code; time=dt+Minute(1), digits=8,
                           allowed_drift=Second(30))
false
```

```jldoctest
julia> using OneTimePasswords, Dates, Random

julia> # secret as `Vector{UInt8}; generate_secret_raw()

julia> dt = DateTime(2022,1,1,0,0,30);

julia> secret_raw = UInt8[0x67, 0xc0, 0x1e, 0xd3, 0x83, 0xa0, 0x9a, 0x8e, 
       0x1a, 0x74, 0x60, 0x58, 0x1e, 0x40, 0x3b, 0x5a, 0xfd, 0x14, 0x19, 0xc5];

julia> code = generate(TOTP(), secret_raw; time=dt, digits=8);

julia> verify(TOTP(), secret_raw, code; time=dt, digits=8)
true

julia> rand!(RandomDevice(), secret_raw);
```
See also [`generate(::TOTP)`](@ref).
"""
function verify(::TOTP, secret::Vector{UInt8}, code::AbstractString;
    period::Union{Period,Integer}=Second(30),
    allowed_drift::Union{Period,Integer}=Second(30),
    digits::Int=6,
    time=nothing,
    algorithm::Symbol=:SHA1)
    t = time === nothing ? Dates.now(UTC) : time
    secs = floor(Int, Dates.datetime2unix(t))
    period_int = period isa Period ? Second(period).value : period
    counter = div(secs, period_int)
    window = Int(div(Second(allowed_drift).value, period_int))
    for δ in -window:window
        # compute candidate OTP for this time‐step
        candidate = generate(HOTP(), secret, counter + δ;
            digits=digits,
            algorithm=algorithm)
        # compare in constant time
        if _consttime_eq(candidate, code)
            return true
        end
    end
    return false
end

function verify(::TOTP, secret::AbstractString, code::AbstractString; kwargs...)
    verify(TOTP(), base32decode(secret), code; kwargs...)
end

"""
    verify(::OCRA, secret::AbstractString, code::AbstractString;
           suite::AbstractString = "OCRA-1:HOTP-SHA1-6:QN08",
           counter::Union{Nothing, Integer}=nothing,
           challenge::AbstractString="",
           password::AbstractString="",
           session_info::AbstractString="",
           timestamp::Union{Nothing,Integer,DateTime}=nothing,
           allowed_drift::Period=Second(0),
           digits::Int=6,
           algorithm::Symbol=:SHA1)::Bool

Verify that the provided code matches the OCRA OTP.

# Examples
```jldoctest
julia> using OneTimePasswords, Dates

julia> # Base32-encoded String secret

julia> secret = generate_secret();

julia> code = generate(OCRA(), secret; challenge="12345678");

julia> verify(OCRA(), secret, code; challenge="12345678")
true
```

```jldoctest
julia> using OneTimePasswords, Dates, Random

julia> # secret as `Vector{UInt8}; generate_secret_raw()

julia> secret_raw = generate_secret_raw();

julia> code = generate(OCRA(), secret_raw; challenge="12345678");

julia> verify(OCRA(), secret_raw, code; challenge="12345678")
true

julia> rand!(RandomDevice(), secret_raw);
```

```jldoctest
julia> using OneTimePasswords, Dates

julia> secret = generate_secret();

julia> suite = "OCRA-1:HOTP-SHA512-8:QA10-T1M";

julia> dt = DateTime(2020,1,1,0,0,30)
2020-01-01T00:00:30

julia> secret = "T6AZ35HKKGWJEUACAUG5MK7T3CBZ5M76Q2GHLMHYOXQEHXKKTATGVH73\
                     QBRRW4MBP4P6QKCVMIMMIIBYEY534KZ\
                     QB6YVK2TE3II3XZA="; # generate_secret(63)

julia> code2 = generate(OCRA(), secret;
                          suite=suite,
                          challenge="SIG1400000",
                          timestamp=dt,
                          digits=8,
                          algorithm=:SHA512);

julia> verify(OCRA(), secret, code2;
               suite=suite,
               challenge="SIG1400000",
               timestamp=dt + Second(60),
               allowed_drift=Second(60),
               digits=8,
               algorithm=:SHA512)
true
```
"""
function verify(::OCRA, secret::Vector{UInt8}, code::AbstractString;
    suite::AbstractString="OCRA-1:HOTP-SHA1-6:QN08",
    counter::Union{Nothing,Integer}=nothing,
    challenge::AbstractString="",
    password::AbstractString="",
    session_info::AbstractString="",
    timestamp::Union{Nothing,Integer,DateTime}=nothing,
    allowed_drift::Period=Second(0),
    digits::Int=6,
    algorithm::Symbol=:SHA1)

    ts_dt::Union{Nothing,DateTime} = timestamp === nothing ? nothing :
                                     timestamp isa DateTime ? timestamp :
                                     unix2datetime(timestamp)

    step = 0
    m = match(r"T(\d+)([SMH])", suite)
    if !isnothing(m)
        n = parse(Int, m.captures[1])
        unit = m.captures[2]
        step = unit == "S" ? n : unit == "M" ? 60 * n : 3600 * n
    end
    window = step == 0 ? 0 : Int(div(Second(allowed_drift).value, step))
    for δ in -window:window
        # shift timestamp / counter by ±δ steps
        tpass = (ts_dt === nothing || step == 0) ? ts_dt :
                ts_dt + Second(δ * step)
        # generate candidate
        expected = generate(OCRA(), secret;
            suite=suite,
            counter=counter,
            challenge=challenge,
            password=password,
            session_info=session_info,
            timestamp=tpass,
            digits=digits,
            algorithm=algorithm)
        # constant-time comparison
        if _consttime_eq(expected, code)
            return true
        end
    end
    return false
end

function verify(::OCRA, secret::AbstractString, code::AbstractString; kwargs...)
    verify(OCRA(), base32decode(secret), code; kwargs...)
end

"""
    uri(::HOTP, secret::AbstractString,
        account::AbstractString, issuer::AbstractString;
        digits::Int=6, counter::Integer=0,
        algorithm::Symbol=:SHA1)::String

Return an `otpauth://hotp/...` provisioning URI for HOTP.

# Examples
```jldoctest
julia> using OneTimePasswords

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> uri(HOTP(), secret, "bob@example.com", "MyApp"; counter=5)
"otpauth://hotp/MyApp%3Abob%40example.com?secret=M7AB5U4DUCNI4GTUMBMB4QB3LL6RI\
GOF&issuer=MyApp&digits=6&counter=5&algorithm=SHA1"
```

See also [`qrcode`](@ref).
"""
function uri(::HOTP, secret::AbstractString,
    account::AbstractString, issuer::AbstractString;
    digits::Int=6,
    counter::Integer=0,
    algorithm::Symbol=:SHA1)
    label = isempty(issuer) ? account : "$(issuer):$(account)"
    params = [
        "secret=$(escapeuri(secret))",
        "issuer=$(escapeuri(issuer))",
        "digits=$(digits)",
        "counter=$(counter)",
        "algorithm=$(uppercase(String(algorithm)))"
    ]
    return "otpauth://hotp/$(escapeuri(label))?" * join(params, "&")
end

"""
    uri(::TOTP, secret::AbstractString,
        account::AbstractString, issuer::AbstractString;
        digits::Int=6, period::Period=Second(30))::String

Return an `otpauth://totp/...` provisioning URI for TOTP.

# Examples
```jldoctest
julia> using OneTimePasswords

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> uri(TOTP(), secret, "alice@example.com", "MyApp");

julia> uri(TOTP(), secret, "bob@site.com", "YourApp"; digits=8, period=60)
"otpauth://totp/YourApp%3Abob%40site.com?secret=M7AB5U4DUCNI4GTUMBMB4QB3LL6RIG\
OF&issuer=YourApp&digits=8&period=60"
```

See also [`qrcode`](@ref).
"""
function uri(::TOTP, secret::AbstractString,
    account::AbstractString, issuer::AbstractString;
    digits::Int=6, period::Union{Period,Integer}=Second(30))
    label = isempty(issuer) ? account : "$(issuer):$(account)"
    period_int = period isa Period ? Second(period).value : period
    params = [
        "secret=$(escapeuri(secret))",
        "issuer=$(escapeuri(issuer))",
        "digits=$(digits)",
        "period=$(period_int)"
    ]
    return "otpauth://totp/$(escapeuri(label))?" * join(params, "&")
end

"""
    uri(::OCRA, secret::AbstractString,
        account::AbstractString, issuer::AbstractString;
        suite::AbstractString="OCRA-1:HOTP-SHA1-6:QN08",
        digits::Int=6,
        algorithm::Symbol=:SHA1,
        counter::Union{Nothing,Int}=nothing,
        challenge::AbstractString="",
        password::AbstractString="",
        session_info::AbstractString="",
        timestamp::Union{Nothing,Int,DateTime}=nothing
       )::String

Return an `otpauth://ocra/...` provisioning URI for OCRA.

The label will be `issuer:account` (percent-escaped),
and the query string will include `secret`, `issuer`, `suite`, `digits`,
`algorithm`, and any of the optional fields you pass in.

```jldoctest
julia> using OneTimePasswords

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> uri(OCRA(), secret, "bob@example.com", "MyApp");

julia> uri(OCRA(), secret, "alice@site.com", "YourOrg";
            suite="OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1",
            digits=8,
            algorithm=:SHA256,
            counter=5,
            challenge="12345678",
            password="7110eda4d09e062aa5e4a390b0a572ac0d2c0220");
```

See also [`qrcode`](@ref).
"""
function uri(::OCRA,
    secret::AbstractString,
    account::AbstractString,
    issuer::AbstractString;
    suite::AbstractString="OCRA-1:HOTP-SHA1-6:QN08",
    digits::Int=6,
    algorithm::Symbol=:SHA1,
    counter::Union{Nothing,Int}=nothing,
    challenge::AbstractString="",
    password::AbstractString="",
    session_info::AbstractString="",
    timestamp::Union{Nothing,Int,DateTime}=nothing)
    # build the label
    label = isempty(issuer) ? account : "$(issuer):$(account)"
    esc_label = escapeuri(label)

    # mandatory params
    params = [
        "secret=$(escapeuri(secret))",
        "issuer=$(escapeuri(issuer))",
        "suite=$(escapeuri(suite))",
        "digits=$(digits)",
        "algorithm=$(uppercase(String(algorithm)))"]

    # optional params
    if counter !== nothing
        push!(params, "counter=$(counter)")
    end
    if !isempty(challenge)
        push!(params, "challenge=$(escapeuri(challenge))")
    end
    if !isempty(password)
        push!(params, "password=$(escapeuri(password))")
    end
    if !isempty(session_info)
        push!(params, "sessioninfo=$(escapeuri(session_info))")
    end
    if timestamp !== nothing
        ts = timestamp isa DateTime ? floor(Int, datetime2unix(timestamp)) :
             timestamp
        push!(params, "timestamp=$(ts)")
    end
    return "otpauth://ocra/$(esc_label)?" * join(params, "&")
end

"""
    exportsvg(
      msg::AbstractString;
      size::Int=240,
      border::Int=4,
      path::Union{Nothing,String}=nothing,
      darkcolor::String="#000",
      lightcolor::String="#fff"
    )::String

Generate an SVG `<svg>…</svg>` QR-code encoding `msg`.
If `path` is given, also write the SVG to that file.

# Examples
```jldoctest
julia> using OneTimePasswords

julia> OneTimePasswords.exportsvg("otpauth://totp/bob?...", size=200);
```

See also [`qrcode`](@ref).
"""
function exportsvg(msg::AbstractString;
    size::Int=240,
    border::Int=4,
    path::Union{Nothing,String}=nothing,
    darkcolor::String="#000",
    lightcolor::String="#fff")
    mat = QRCoders.qrcode(msg; width=border)
    n = Base.size(mat, 1)
    sc = size ÷ n
    io = IOBuffer()
    println(io, "<svg xmlns=\"http://www.w3.org/2000/svg\" ",
        "width=\"$(n*sc)\" height=\"$(n*sc)\" viewBox=\"0 0 $n $n\">")
    println(io, "<rect width=\"$n\" height=\"$n\" fill=\"$lightcolor\"/>")
    for y in 1:n, x in 1:n
        mat[y, x] && println(io,
            "<rect x=\"$(x-1)\" y=\"$(y-1)\" width=\"1\" height=\"1\" ",
            "fill=\"$darkcolor\"/>")
    end
    println(io, "</svg>")
    svg = String(take!(io))
    if path !== nothing
        open(path, "w") do f
            write(f, svg)
        end
    end
    return svg
end

"""
    qrcode(
      uri::AbstractString;
      format::Union{Symbol,String} = :svg,
      size::Int = 240,
      border::Int = 4,
      path::Union{Nothing,String} = nothing,
      darkcolor::String = "#000",
      lightcolor::String = "#fff"
    )::Union{String,String}

Generate a QR-code for a provisioning `uri`.  Supports:
- SVG (`:svg`, returns SVG text),
- Bitmap (`"png"`, `"jpg"`, `"gif"`, writes to `path`) and
- Terminal ASCII (`:ascii`, prints a scannable QR code in the REPL).

# Examples
```jldoctest
julia> using OneTimePasswords, Dates

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> code = generate(TOTP(), secret; period=Second(30), digits=6);

julia> verify(TOTP(), secret, code; allowed_drift=Second(30))
true

julia> urilink = uri(TOTP(), secret, "bob@example.com", "MyApp"; digits=6, 
       period=Second(30));

julia> svg = qrcode(urilink; format=:svg, size=200, border=2);

julia> tmp_svg = tempname() * ".svg";

julia> open(tmp_svg, "w") do io
           write(io, svg)
       end;

julia> tmp_png = tempname() * ".png";

julia> pngfile = qrcode(urilink; format="png", path=tmp_png);

julia> isfile(pngfile)
true

julia> # qrcode(urilink; format=:ascii, border=1) # Print in the REPL
```

See also [`uri`](@ref) and [`exportsvg`](@ref).
"""
function qrcode(uri::AbstractString;
    format::Union{Symbol,String}=:svg,
    size::Int=240,
    border::Int=4,
    path::Union{Nothing,String}=nothing,
    darkcolor::String="#000",
    lightcolor::String="#fff")
    fmt = lowercase(string(format))
    if fmt == "ascii"
        # Terminal-friendly QR
        mat = QRCoders.qrcode(uri; width=border)
        for row in eachrow(mat)
            println(join(map(x -> x ? "██" : "  ", row)))
        end
        return nothing
    elseif fmt == "svg"
        return exportsvg(uri; size=size,
            border=border,
            path=path,
            darkcolor=darkcolor,
            lightcolor=lightcolor)
    end
    allowed = ("png", "jpg", "jpeg", "gif")
    fmt ∉ allowed && error("Unsupported format: $format. Use :svg or one 
    of $(allowed).")
    path === nothing && error("`path` must be given when format != :svg")
    mat = QRCoders.qrcode(uri; width=border)
    QRCoders.exportbitmat(mat, path; pixels=size)
    return path
end

function _check_digits(d::Int)
    if d < 6 || d > 10
        error("Invalid digits=$d: RFC4226 requires between 6 and 10 digits")
    #if d < 4 || d > 10
    #    error("Invalid digits=$d: must be between 4 and 10")
    end
    return d
end

using Base: codeunit

function _consttime_eq(a::AbstractString, b::AbstractString)
    la, lb = sizeof(a), sizeof(b)
    # Early exit if lengths differ
    if la != lb
        return false
    end
    acc = UInt8(0)
    # XOR each pair of bytes and OR into acc
    for i in 1:la
        acc |= UInt8(codeunit(a, i) ⊻ codeunit(b, i))
    end
    return acc == 0
end

function _check_secret_length(algorithm::Symbol, key::Vector{UInt8})
    minlen = algorithm === :SHA1 ? 20 :
             algorithm === :SHA256 ? 32 :
             algorithm === :SHA512 ? 64 :
             error("Unknown algorithm: $algorithm")
    if length(key) < minlen
        error("Secret too short for 
        $algorithm (need ≥$minlen bytes, got $(length(key)))")
    end
    return key
end

end
