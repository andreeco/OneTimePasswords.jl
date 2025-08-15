# OTPs

[![Stable](https://img.shields.io/badge/docs-stable-blue.svg)](https://andreeco.github.io/OTPs.jl/stable/)
[![Dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://andreeco.github.io/OTPs.jl/dev/)
[![Build Status](https://github.com/andreeco/OTPs.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/andreeco/OTPs.jl/actions/workflows/CI.yml?query=branch%3Amain)
[![Coverage](https://codecov.io/gh/andreeco/OTPs.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/andreeco/OTPs.jl)

A minimal, fast Julia module for generating and verifying
counter-based (HOTP, RFC 4226) and time-based (TOTP, RFC 6238)
one-time passwords.  Also provides provisioning URIs and QR-codes
for authenticator apps.

## Installation

```julia
using Pkg
Pkg.add("OTPs")
```

## Quickstart

```julia
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

## Documentation

Full docs are auto-published at  
https://andreeco.github.io/OTPs.jl/dev

## API at a glance

- `OTPs.HOTP()`, `OTPs.TOTP()`  
- `generate_secret()`  
- `generate(::HOTP, secret, counter; digits, algorithm)`  
- `generate(::TOTP, secret; time, period, digits, algorithm)`  
- `verify(::HOTP, ...)`, `verify(::TOTP, ...)`  
- `uri(::HOTP/::TOTP, secret, account, issuer; ...)`  
- `qrcode(uri; format, size, border, path)`  
- `exportsvg(msg; size, border, path, darkcolor, lightcolor)`  
- `base32encode/ base32decode`

See the [full Reference](https://andreeco.github.io/OTPs.jl/dev/api/) for 
details on every function and keyword.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.