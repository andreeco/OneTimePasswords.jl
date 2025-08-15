#https://datatracker.ietf.org/doc/rfc6238/
#https://datatracker.ietf.org/doc/html/rfc4226

using Test
using Dates, HTTP, CodecBase, OTPs

@testset "OTPs – Full Test Suite" begin

  @testset "Base32 encode/decode – roundtrip and drift" begin
    # RFC 4648 vectors
    pairs = [
      ("", ""),
      ("f", "MY======"),
      ("fo", "MZXQ===="),
      ("foo", "MZXW6==="),
      ("foob", "MZXW6YQ="),
      ("fooba", "MZXW6YTB"),
      ("foobar", "MZXW6YTBOI======"),
    ]
    for (plain, b32) in pairs
      b32gen = OTPs.base32encode(Vector{UInt8}(plain))
      @test b32gen == b32
      out = OTPs.base32decode(b32)
      @test String(out) == plain
    end

    # Reversibility / surjectivity
    for n in 0:32
      orig  = rand(UInt8, n)
      code  = OTPs.base32encode(orig)
      round = OTPs.base32decode(code)
      @test round == orig
      @test typeof(round) == Vector{UInt8}
    end

    # CRC‐style error (optional)
    data = UInt8[0xde,0xad,0xbe,0xef]
    code = OTPs.base32encode(data)
    mut  = code[1] != 'A' ? replace(code, code[1] => 'A'; count=1) :
                              replace(code, code[1] => 'B'; count=1)
    # @test_throws Exception OTPs.base32decode(mut)
  end

  @testset "Secret generation – randomness, uniqueness" begin
    seen = Set{String}()
    for i in 1:30
      sec = OTPs.generate_secret(32)
      out = OTPs.base32decode(sec)
      @test length(out) == 32
      @test sec ∉ seen
      push!(seen, sec)
      @test all(isascii, sec)
    end
    # Only A–Z, 2–7, '='
    sec64 = OTPs.generate_secret(64)
    @test all(c->c in 'A':'Z' || c in '2':'7' || c=='=', sec64)
  end

  @testset "RFC 4226 HOTP test vectors" begin
    # ASCII secret and its Base32
    ascii = "12345678901234567890"
    b32   = OTPs.base32encode(Vector{UInt8}(ascii))
    # Expected 6-digit HOTP for counts 0–9
    expected = ["755224","287082","359152","969429","338314",
                "254676","287922","162583","399871","520489"]
    for count in 0:9
      exp = expected[count+1]
      got = OTPs.generate(OTPs.HOTP(), b32, count)
      @test got == exp
      @test OTPs.verify(OTPs.HOTP(), b32, count, exp)
    end
  end

  @testset "RFC 6238 TOTP test vectors" begin
    ascii_secrets = Dict(
      :SHA1   => "12345678901234567890",
      :SHA256 => "12345678901234567890123456789012",
      :SHA512 => "1234567890123456789012345678901234567890123456789012345678901234"
    )
    secrets = Dict(algo => OTPs.base32encode(Vector{UInt8}(ascii_secrets[algo]))
                   for algo in keys(ascii_secrets))

    rfc = [
      (59,         "94287082","46119246","90693936"),
      (1111111109, "07081804","68084774","25091201"),
      (1111111111, "14050471","67062674","99943326"),
      (1234567890, "89005924","91819424","93441116"),
      (2000000000, "69279037","90698825","38618901"),
      (20000000000,"65353130","77737706","47863826"),
    ]
    algos = [:SHA1, :SHA256, :SHA512]

    for (i, algo) in enumerate(algos)
      b32 = secrets[algo]
      for (t, c1, c2, c3) in rfc
        exp = (c1,c2,c3)[i]
        dt  = DateTime(1970,1,1) + Second(t)
        got = OTPs.generate(OTPs.TOTP(), b32;
                             time=dt, digits=8,
                             period=30, algorithm=algo)
        @test got == exp
        @test OTPs.verify(OTPs.TOTP(), b32, exp;
                              time=dt, digits=8,
                              period=30, algorithm=algo)
      end
    end
  end

  @testset "TOTP with different periods and digits" begin
    sec = OTPs.generate_secret(32)
    c4 = OTPs.generate(OTPs.TOTP(), sec; digits=4, period=15)
    @test length(c4) == 4
    @test all(isdigit, c4)

    c7 = OTPs.generate(OTPs.TOTP(), sec; digits=7, period=60)
    @test length(c7) == 7
    @test all(isdigit, c7)
  end

  @testset "URI formatting – HOTP & TOTP" begin
    b32 = OTPs.base32encode(Vector{UInt8}("1234"))
    hotp_uri = OTPs.uri(OTPs.HOTP(), b32, "u","S"; digits=6,
                        counter=5, algorithm=:SHA1)
    @test startswith(hotp_uri, "otpauth://hotp/")
    @test occursin("secret=$b32", hotp_uri)
    @test occursin("counter=5", hotp_uri)
    @test occursin("algorithm=SHA1", hotp_uri)

    totp_uri = OTPs.uri(OTPs.TOTP(), b32, "u","S"; digits=6, period=30)
    @test startswith(totp_uri, "otpauth://totp/")
    @test occursin("secret=$b32", totp_uri)
    @test occursin("period=30", totp_uri)
  end

  @testset "TOTP verification – drift and invalid" begin
    sec = OTPs.generate_secret()
    now = Dates.now(UTC)
    code = OTPs.generate(OTPs.TOTP(), sec; time=now)

    # current period
    @test OTPs.verify(OTPs.TOTP(), sec, code; time=now)

    # ±1 step
    @test OTPs.verify(OTPs.TOTP(), sec, code; time=now+Second(30))
    @test OTPs.verify(OTPs.TOTP(), sec, code; time=now-Second(30))

    # outside default drift
    @test !OTPs.verify(OTPs.TOTP(), sec, code; time=now+Second(60))

    # allow drift=2
    @test OTPs.verify(OTPs.TOTP(), sec, code;
                          time=now+Second(60),
                          allowed_drift=2)

    # random invalid
    bad = code=="999999" ? "000000" : "999999"
    @test !OTPs.verify(OTPs.TOTP(), sec, bad; allowed_drift=0)
  end

  @testset "Edge cases & error handling" begin
    # invalid Base32
    @test_throws Exception OTPs.base32decode("!")

    # minimum digits = 1
    s = OTPs.generate_secret()
    c = OTPs.generate(OTPs.TOTP(), s; digits=1)
    @test length(c) == 1

    # empty secret
    @test !OTPs.verify(OTPs.TOTP(), "", c)

    # invalid padding
    @test_throws Exception OTPs.base32decode("A=====")
  end

  @testset "Unicode / escaping in URIs" begin
    sec = OTPs.generate_secret(20)
    acc = "Björk O’Conor"
    iss = "🌞Sun/Örganization"
    u = OTPs.uri(OTPs.TOTP(), sec, acc, iss)
    @test occursin(HTTP.URIs.escapeuri(acc), u)
    @test occursin(HTTP.URIs.escapeuri(iss), u)
  end

  @testset "Round‐trip secret → URI" begin
    s   = OTPs.generate_secret(32)
    code = OTPs.generate(OTPs.TOTP(), s)
    u    = OTPs.uri(OTPs.TOTP(), s, "bob","ex"; digits=6, period=30)
    @test occursin(s, u)
  end

  @testset "QR‐code helpers (SVG & PNG)" begin
    b32 = OTPs.base32encode(Vector{UInt8}("1234"))
    huri = OTPs.uri(OTPs.HOTP(), b32, "u","S"; counter=1)
    turi = OTPs.uri(OTPs.TOTP(), b32, "u","S"; period=30)

    # SVG for HOTP
    svg1 = OTPs.qrcode(huri; format=:svg, size=80, border=1)
    @test startswith(svg1, "<svg")
    # SVG for TOTP
    svg2 = OTPs.qrcode(turi; format=:svg)
    @test startswith(svg2, "<svg")

    # PNG for HOTP
    tmp = tempname()*".png"
    path = OTPs.qrcode(huri; format="png", path=tmp)
    @test path == tmp
    @test isfile(tmp)
    bytes = read(tmp)
    @test bytes[1:8] == UInt8[0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]
    rm(tmp; force=true)

    # unsupported / missing path
    @test_throws ErrorException OTPs.qrcode(huri; format="bmp", path="foo.bmp")
    @test_throws ErrorException OTPs.qrcode(huri; format="jpg")
  end

end
