"""
    module OTPs

A minimal, fast Julia module for generating and verifying
counter-based (HOTP, RFC 4226) and time-based (TOTP, RFC 6238)
one-time passwords.  Also provides provisioning URIs and QR-codes
for authenticator apps.

# Examples
```jldoctest
julia> using OTPs

julia> secret = generate_secret();

julia> code1 = generate(HOTP(), secret, 0; digits=6);

julia> verify(HOTP(), secret, 0, code1)
true

julia> code2 = generate(TOTP(), secret; period=30, digits=6);

julia> verify(TOTP(), secret, code2; allowed_drift=1)
true

julia> urilink = uri(TOTP(), secret, "bob@example.com", "MyApp"; digits=6, 
       period=30);

julia> svg = qrcode(urilink; format=:svg, size=200, border=2);

julia> tmp_svg = tempname() * ".svg";

julia> open(tmp_svg, "w") do io
           write(io, svg)
       end;

julia> tmp_png = tempname() * ".png";

julia> pngfile = qrcode(urilink; format="png", path=tmp_png);

julia> isfile(pngfile)
true
```

# See also
- [`base32encode`](@ref) / [`base32decode`](@ref)  
- [`generate_secret`](@ref)  
- [`HOTP`](@ref), [`TOTP`](@ref)  
- [`generate`](@ref), [`verify`](@ref)  
- [`uri`](@ref), [`qrcode`](@ref)
"""
module OTPs

using Dates
using SHA
using Random
using HTTP.URIs: escapeuri
using CodecBase
using QRCoders

export base32encode, base32decode, generate_secret
export AbstractOTP, HOTP, TOTP
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
    generate_secret([length::Int=20])::String

Generate a cryptographically-strong random secret (byte length `length`)
and return it Base32-encoded.  Default is 20 bytes (good for SHA1/TOTP).

# Examples
```jldoctest
julia> using OTPs

julia> secret = generate_secret();
```

See also [`base32encode`](@ref), [`base32decode`](@ref).
"""
function generate_secret(length::Int=20)
    rd = Random.RandomDevice()
    bytes = rand(rd, UInt8, length)
    base32encode(bytes)
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
    generate(::HOTP, secret::AbstractString, counter::Integer;
             digits::Int=6, algorithm::Symbol=:SHA1)::String

Compute HOTP for `secret` and `counter` (RFC 4226).

# Arguments
- `secret`: Base32-encoded shared secret.
- `counter`: counter value (Integer).
- `digits`: code length (default 6).
- `algorithm`: `:SHA1`, `:SHA256`, or `:SHA512`.

# Examples
```jldoctest
julia> using OTPs

julia> generate(HOTP(), "JBSWY3DPEHPK3PXP", 0)
"282760"
```

See also [`verify(::HOTP)`](@ref), [`generate(::TOTP)`](@ref) and 
[`verify(::TOTP)`](@ref).
"""
function generate(::HOTP, secret::AbstractString, counter::Integer;
    digits::Int=6, algorithm::Symbol=:SHA1)
    key = base32decode(secret)
    msg = zeros(UInt8, 8)
    for i in 1:8
        msg[9-i] = (counter >> (8 * (i - 1))) & 0xff
    end
    h = algorithm === :SHA1 ? SHA.hmac_sha1(key, msg) :
        algorithm === :SHA256 ? SHA.hmac_sha256(key, msg) :
        algorithm === :SHA512 ? SHA.hmac_sha512(key, msg) :
        error("Unknown algorithm $algorithm")
    off = h[end] & 0x0f
    code = (UInt32(h[off+1] & 0x7f) << 24) |
           (UInt32(h[off+2]) << 16) |
           (UInt32(h[off+3]) << 8) |
           UInt32(h[off+4])
    s = lpad(string(code % UInt32(10^digits)), digits, '0')
    return s
end

"""
    generate(::TOTP, secret::AbstractString;
             time=nothing, period::Int=30, digits::Int=6,
             algorithm::Symbol=:SHA1)::String

Compute a TOTP value for `secret` at the specified `time`
(RFC 6238), with integer step-countging.

# Examples

```jldoctest
julia> using OTPs, Dates

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> generate(TOTP(), secret; digits=8);

julia> dt = DateTime(2020,1,1,0,0,30);

julia> generate(TOTP(), secret; time=dt, digits=7, period=30, algorithm=:SHA256)
"9150483"
```

See also [`verify(::TOTP)`](@ref), [`generate(::HOTP)`](@ref) and 
[`verify(::HOTP)`](@ref).
"""
function generate(::TOTP, secret::AbstractString;
    time=nothing,
    period::Int=30,
    digits::Int=6,
    algorithm::Symbol=:SHA1)
    t = time === nothing ? Dates.now(UTC) : time
    secs = floor(Int, Dates.datetime2unix(t))
    counter = div(secs, period)
    return generate(HOTP(), secret, counter;
        digits=digits,
        algorithm=algorithm)
end

"""
    verify(::HOTP, secret::AbstractString, counter::Integer,
           code::AbstractString; digits::Int=6,
           algorithm::Symbol=:SHA1)::Bool

Return `true` if `code` matches the HOTP for `secret` and `counter`.

# Examples
```jldoctest
julia> using OTPs

julia> secret = generate_secret();

julia> code = generate(HOTP(), secret, 123; digits=6);

julia> verify(HOTP(), secret, 123, code)
true

julia> verify(HOTP(), secret, 124, code)
false
```

See also [`generate(::HOTP)`](@ref).
"""
verify(::HOTP, secret::AbstractString, counter::Integer,
    code::AbstractString; digits::Int=6,
    algorithm::Symbol=:SHA1) =
    generate(HOTP(), secret, counter;
        digits=digits, algorithm=algorithm) === code

"""
    verify(::TOTP, secret::AbstractString, code::AbstractString;
           period::Int=30, allowed_drift::Int=1,
           digits::Int=6, time=nothing,
           algorithm::Symbol=:SHA1)::Bool

Return `true` if `code` is a valid TOTP for `secret` at `time`, allowing
±`allowed_drift` time steps.

# Examples
```jldoctest
julia> using OTPs, Dates

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> dt = DateTime(2022,1,1,0,0,30);

julia> code = generate(TOTP(), secret; time=dt, digits=8);

julia> verify(TOTP(), secret, code; time=dt, digits=8)
true

julia> verify(TOTP(), secret, code; time=dt+Minute(1), digits=8,
                           allowed_drift=2)
true

julia> verify(TOTP(), secret, code; time=dt+Minute(1), digits=8,
                           allowed_drift=1)
false
```

See also [`generate(::TOTP)`](@ref).
"""
function verify(::TOTP, secret::AbstractString, code::AbstractString;
    period::Int=30,
    allowed_drift::Int=1,
    digits::Int=6,
    time=nothing,
    algorithm::Symbol=:SHA1)
    t = time === nothing ? Dates.now(UTC) : time
    secs = floor(Int, Dates.datetime2unix(t))
    counter = div(secs, period)
    for δ in -allowed_drift:allowed_drift
        if generate(HOTP(), secret, counter + δ;
            digits=digits, algorithm=algorithm) == code
            return true
        end
    end
    return false
end

"""
    uri(::HOTP, secret::AbstractString,
        account::AbstractString, issuer::AbstractString;
        digits::Int=6, counter::Integer=0,
        algorithm::Symbol=:SHA1)::String

Return an `otpauth://hotp/...` provisioning URI for HOTP.

# Examples
```jldoctest
julia> using OTPs

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> uri(HOTP(), secret, "bob@example.com", "MyApp"; counter=5)
"otpauth://hotp/MyApp%3Abob%40example.com?secret=M7AB5U4DUCNI4GTUMBMB4QB\
3LL6RIGOF&issuer=MyApp&digits=6&counter=5&algorithm=SHA1"
```

See also [`uri(::TOTP)`](@ref), [`qrcode`](@ref).
"""
function uri(::HOTP, secret::AbstractString,
    account::AbstractString, issuer::AbstractString;
    digits::Int=6,
    counter::Integer=0,
    algorithm::Symbol=:SHA1)
    label = isempty(issuer) ? account : "$(issuer):$(account)"
    params = [
        "secret=$secret",
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
        digits::Int=6, period::Int=30)::String

Return an `otpauth://totp/...` provisioning URI for TOTP.

# Examples
```jldoctest
julia> using OTPs

julia> secret = "M7AB5U4DUCNI4GTUMBMB4QB3LL6RIGOF"; # generate_secret()

julia> uri(TOTP(), secret, "alice@example.com", "MyApp");

julia> uri(TOTP(), secret, "bob@site.com", "YourApp"; digits=8, period=60)
"otpauth://totp/YourApp%3Abob%40site.com?secret=M7AB5U4DUCNI4GTUMBMB4QB3LL6RIG\
OF&issuer=YourApp&digits=8&period=60"
```

See also [`uri(::HOTP)`](@ref), [`qrcode`](@ref).
"""
function uri(::TOTP, secret::AbstractString,
    account::AbstractString, issuer::AbstractString;
    digits::Int=6, period::Int=30)
    label = isempty(issuer) ? account : "$(issuer):$(account)"
    params = [
        "secret=$secret",
        "issuer=$(escapeuri(issuer))",
        "digits=$(digits)",
        "period=$(period)"
    ]
    return "otpauth://totp/$(escapeuri(label))?" * join(params, "&")
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
julia> using OTPs

julia> OTPs.exportsvg("otpauth://totp/bob?...", size=200);
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
- Bitmap (`"png"`, `"jpg"`, `"gif"`, writes to `path`).

# Examples
```jldoctest
julia> using OTPs

julia> secret = generate_secret();

julia> code1 = generate(HOTP(), secret, 0; digits=6);

julia> verify(HOTP(), secret, 0, code1)
true

julia> code2 = generate(TOTP(), secret; period=30, digits=6);

julia> verify(TOTP(), secret, code2; allowed_drift=1)
true

julia> urilink = uri(TOTP(), secret, "bob@example.com", "MyApp"; digits=6, 
       period=30);

julia> svg = qrcode(urilink; format=:svg, size=200, border=2);

julia> tmp_svg = tempname() * ".svg";

julia> open(tmp_svg, "w") do io
           write(io, svg)
       end;

julia> tmp_png = tempname() * ".png";

julia> pngfile = qrcode(urilink; format="png", path=tmp_png);

julia> isfile(pngfile)
true
```

See also [`uri`](@ref), [`exportsvg`](@ref).
"""
function qrcode(uri::AbstractString;
    format::Union{Symbol,String}=:svg,
    size::Int=240,
    border::Int=4,
    path::Union{Nothing,String}=nothing,
    darkcolor::String="#000",
    lightcolor::String="#fff")
    fmt = lowercase(string(format))
    if fmt == "svg"
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
end
