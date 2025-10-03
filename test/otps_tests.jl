#https://datatracker.ietf.org/doc/rfc6238/
#https://datatracker.ietf.org/doc/html/rfc4226
#https://datatracker.ietf.org/doc/html/rfc6287

using Test
using Dates, HTTP, CodecBase, OneTimePasswords

@testset "OneTimePasswords - Full Test Suite" begin

  @testset "Base32 encode/decode - RFC 4648 and roundtrip" begin
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
      b32gen = OneTimePasswords.base32encode(Vector{UInt8}(plain))
      @test b32gen == b32
      out = OneTimePasswords.base32decode(b32)
      @test String(out) == plain
    end

    # Round‐trip for random data
    for n in 0:32
      orig = rand(UInt8, n)
      code = OneTimePasswords.base32encode(orig)
      round = OneTimePasswords.base32decode(code)
      @test round == orig
      @test typeof(round) == Vector{UInt8}
    end
  end

  @testset "Secret generation - randomness & charset" begin
    seen = Set{String}()
    for i in 1:30
      sec = OneTimePasswords.generate_secret(32)
      out = OneTimePasswords.base32decode(sec)
      @test length(out) == 32
      @test sec ∉ seen
      push!(seen, sec)
      @test all(isascii, sec)
    end
    # Only A-Z, 2-7, =
    sec64 = OneTimePasswords.generate_secret(64)
    @test all(c -> c in 'A':'Z' || c in '2':'7' || c == '=', sec64)
  end

  @testset "RFC 4226 HOTP test vectors" begin
    ascii = "12345678901234567890"
    b32 = OneTimePasswords.base32encode(Vector{UInt8}(ascii))
    expected = ["755224", "287082", "359152", "969429", "338314",
      "254676", "287922", "162583", "399871", "520489"]
    for count in 0:9
      exp = expected[count+1]
      got = OneTimePasswords.generate(OneTimePasswords.HOTP(), b32, count)
      @test got == exp
      @test OneTimePasswords.verify(OneTimePasswords.HOTP(), b32, count, exp)
    end
  end

  @testset "HOTP verification security" begin
    secret = OneTimePasswords.base32encode(Vector{UInt8}(
      "12345678901234567890"))
    # code from RFC 4226 vector
    code0 = OneTimePasswords.generate(OneTimePasswords.HOTP(), secret, 0;
      digits=6)
    # Ensure equality works (not object identity ===)
    @test OneTimePasswords.verify(OneTimePasswords.HOTP(), secret, 0,
      string(code0))
    # Ensure freshly constructed string (different object but same value) still validates
    code_copy = string(code0)  # new object
    @test OneTimePasswords.verify(OneTimePasswords.HOTP(), secret, 0,
      code_copy)
  end

  @testset "Constant-time comparison helper" begin
    # import the helper from the module
    ct = OneTimePasswords._consttime_eq

    # equal strings → true
    @test ct("123456", "123456")
    # same length but one byte differs → false
    @test !ct("abcdef", "abcdez")
    # different lengths → false
    @test !ct("short", "shorter")
    @test !ct("", "nonempty")
    @test !ct("nonempty", "")
  end

  @testset "RFC 6238 TOTP test vectors (SHA1, SHA256, SHA512)" begin
    ascii_secrets = Dict(
      :SHA1 => "12345678901234567890",
      :SHA256 => "12345678901234567890123456789012",
      :SHA512 => "1234567890123456789012345678901234567890123456789012345678901234"
    )
    secrets = Dict(algo => OneTimePasswords.base32encode(Vector{UInt8}(
      ascii_secrets[algo]))
                   for algo in keys(ascii_secrets))

    rfc = [
      (59, "94287082", "46119246", "90693936"),
      (1111111109, "07081804", "68084774", "25091201"),
      (1111111111, "14050471", "67062674", "99943326"),
      (1234567890, "89005924", "91819424", "93441116"),
      (2000000000, "69279037", "90698825", "38618901"),
      (20000000000, "65353130", "77737706", "47863826"),
    ]
    algos = [:SHA1, :SHA256, :SHA512]

    for (i, algo) in enumerate(algos)
      b32 = secrets[algo]
      for (t, c1, c2, c3) in rfc
        exp = (c1, c2, c3)[i]
        dt = DateTime(1970, 1, 1) + Second(t)
        got = OneTimePasswords.generate(OneTimePasswords.TOTP(), b32;
          time=dt, digits=8, period=30, algorithm=algo)
        @test got == exp
        @test OneTimePasswords.verify(OneTimePasswords.TOTP(), b32, exp;
          time=dt, digits=8, period=30, algorithm=algo)
      end
    end
  end

@testset "TOTP with custom period & digits" begin
    sec = OneTimePasswords.generate_secret(32)

    c6 = OneTimePasswords.generate(TOTP(), sec; digits=6, period=15)
    @test length(c6) == 6
    @test all(isdigit, c6)

    c7 = OneTimePasswords.generate(TOTP(), sec; digits=7, period=60)
    @test length(c7) == 7
    @test all(isdigit, c7)
end

  @testset "TOTP verification - drift and invalid" begin
    sec = OneTimePasswords.generate_secret()
    now = Dates.now(UTC)
    code = OneTimePasswords.generate(OneTimePasswords.TOTP(), sec; time=now)

    # exact
    @test OneTimePasswords.verify(OneTimePasswords.TOTP(), sec, code; time=now)
    # ±1 period
    @test OneTimePasswords.verify(OneTimePasswords.TOTP(), sec, code;
      time=now + Second(30))
    @test OneTimePasswords.verify(OneTimePasswords.TOTP(), sec, code;
      time=now - Second(30))
    # outside default drift
    @test !OneTimePasswords.verify(OneTimePasswords.TOTP(), sec, code;
      time=now + Second(60))
    # allow drift=1 minute
    @test OneTimePasswords.verify(OneTimePasswords.TOTP(), sec, code;
      time=now + Second(60),
      allowed_drift=Second(60))
    # random invalid
    bad = code == "999999" ? "000000" : "999999"
    @test !OneTimePasswords.verify(OneTimePasswords.TOTP(), sec, bad; allowed_drift=Second(0))
  end

  # Helper for OCRA interop tests
  hex2b32(hexstr) = begin
    bytes = parse.(UInt8, collect(Iterators.partition(hexstr, 2)), base=16)
    OneTimePasswords.base32encode(bytes)
  end
  PIN_HASH = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"

  @testset "RFC 6287 OCRA-v1 Appendix C Interop" begin
    secret20 = hex2b32("3132333435363738393031323334353637383930")
    secret32 = hex2b32(
      "3132333435363738393031323334353637383930313233343536373839303132")
    secret64 = hex2b32(
      "313233343536373839303132333435363738393031323334353637383930" *
      "313233343536373839303132333435363738393031323334353637383930" *
      "31323334")

    @testset "OCRA padding correctness" begin
      # From RFC 6287 Appendix C.1
      secret20 = OneTimePasswords.base32encode(Vector{UInt8}("12345678901234567890"))
      suite = "OCRA-1:HOTP-SHA1-6:QN08"
      # numeric challenge "00000000" should give 237653
      code = OneTimePasswords.generate(OneTimePasswords.OCRA(),
        secret20; suite=suite, challenge="00000000")
      @test code == "237653"
      # If padding was wrong (rpad), this value would differ.
    end

    @testset "C.1 HOTP-SHA1-6:QN08 (20-byte key)" begin
      suite = "OCRA-1:HOTP-SHA1-6:QN08"
      vects = Dict(
        "00000000" => "237653", "11111111" => "243178", "22222222" => "653583",
        "33333333" => "740991", "44444444" => "608993", "55555555" => "388898",
        "66666666" => "816933", "77777777" => "224598", "88888888" => "750600",
        "99999999" => "294470"
      )
      for (q, exp) in vects
        got = OneTimePasswords.generate(OCRA(), secret20; suite=suite, challenge=q)
        @test got == exp
        @test OneTimePasswords.verify(OCRA(), secret20, exp; suite=suite, challenge=q)
      end
    end

    @testset "C.1 HOTP-SHA256-8:C-QN08-PSHA1 (32-byte key)" begin
      suite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
      vects = [
        (0, "12345678", "65347737"),
        (1, "12345678", "86775851"),
        (2, "12345678", "78192410"),
        (3, "12345678", "71565254"),
        (4, "12345678", "10104329"),
        (5, "12345678", "65983500"),
        (6, "12345678", "70069104"),
        (7, "12345678", "91771096"),
        (8, "12345678", "75011558"),
        (9, "12345678", "08522129"),
      ]
      for (ctr, q, exp) in vects
        got = OneTimePasswords.generate(OCRA(), secret32;
          suite=suite, counter=ctr, challenge=q,
          digits=8, algorithm=:SHA256, password=PIN_HASH)
        @test got == exp
        @test OneTimePasswords.verify(OCRA(), secret32, exp;
          suite=suite, counter=ctr, challenge=q,
          digits=8, algorithm=:SHA256, password=PIN_HASH)
      end
    end

    @testset "C.2 Mutual CR SHA256-8:QA08 (32-byte key)" begin
      suite = "OCRA-1:HOTP-SHA256-8:QA08"
      srv = Dict(
        "CLI22220SRV11110" => "28247970",
        "CLI22221SRV11111" => "01984843",
        "CLI22222SRV11112" => "65387857",
        "CLI22223SRV11113" => "03351211",
        "CLI22224SRV11114" => "83412541"
      )
      for (q, exp) in srv
        @test OneTimePasswords.generate(OCRA(), secret32;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA256) == exp
        @test OneTimePasswords.verify(OCRA(), secret32, exp;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA256)
      end
      cli = Dict(
        "SRV11110CLI22220" => "15510767",
        "SRV11111CLI22221" => "90175646",
        "SRV11112CLI22222" => "33777207",
        "SRV11113CLI22223" => "95285278",
        "SRV11114CLI22224" => "28934924"
      )
      for (q, exp) in cli
        @test OneTimePasswords.generate(OCRA(), secret32;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA256) == exp
        @test OneTimePasswords.verify(OCRA(), secret32, exp;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA256)
      end
    end

    @testset "C.2 Mutual CR SHA512-8:QA08 / QA08-PSHA1 (64-byte key)" begin
      suite_srv = "OCRA-1:HOTP-SHA512-8:QA08"
      suite_cli = "OCRA-1:HOTP-SHA512-8:QA08-PSHA1"
      srv64 = Dict(
        "CLI22220SRV11110" => "79496648",
        "CLI22221SRV11111" => "76831980",
        "CLI22222SRV11112" => "12250499",
        "CLI22223SRV11113" => "90856481",
        "CLI22224SRV11114" => "12761449"
      )
      for (q, exp) in srv64
        @test OneTimePasswords.generate(OCRA(), secret64;
          suite=suite_srv, challenge=q,
          digits=8, algorithm=:SHA512) == exp
        @test OneTimePasswords.verify(OCRA(), secret64, exp;
          suite=suite_srv, challenge=q,
          digits=8, algorithm=:SHA512)
      end
      cli64 = Dict(
        "SRV11110CLI22220" => "18806276",
        "SRV11111CLI22221" => "70020315",
        "SRV11112CLI22222" => "01600026",
        "SRV11113CLI22223" => "18951020",
        "SRV11114CLI22224" => "32528969"
      )
      for (q, exp) in cli64
        @test OneTimePasswords.generate(OCRA(), secret64;
          suite=suite_cli, challenge=q,
          digits=8, algorithm=:SHA512, password=PIN_HASH) == exp
        @test OneTimePasswords.verify(OCRA(), secret64, exp;
          suite=suite_cli, challenge=q,
          digits=8, algorithm=:SHA512, password=PIN_HASH)
      end
    end

    @testset "C.3 Signature SHA256-8:QA08 (32-byte key)" begin
      suite = "OCRA-1:HOTP-SHA256-8:QA08"
      sigs = Dict(
        "SIG10000" => "53095496",
        "SIG11000" => "04110475",
        "SIG12000" => "31331128",
        "SIG13000" => "76028668",
        "SIG14000" => "46554205",
      )
      for (q, exp) in sigs
        @test OneTimePasswords.generate(OCRA(), secret32;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA256) == exp
        @test OneTimePasswords.verify(OCRA(), secret32, exp;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA256)
      end
    end

    @testset "C.3 Signature SHA512-8:QA10-T1M (64-byte key)" begin
      suite = "OCRA-1:HOTP-SHA512-8:QA10-T1M"
      t = parse(Int, "132d0b6", base=16)
      sigs64 = Dict(
        "SIG1000000" => "77537423",
        "SIG1100000" => "31970405",
        "SIG1200000" => "10235557",
        "SIG1300000" => "95213541",
        "SIG1400000" => "65360607",
      )
      for (q, exp) in sigs64
        @test OneTimePasswords.generate(OCRA(), secret64;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA512, timestamp=t) == exp
        @test OneTimePasswords.verify(OCRA(), secret64, exp;
          suite=suite, challenge=q,
          digits=8, algorithm=:SHA512, timestamp=t)
      end
    end
  end

  @testset "OCRA time-based window (allowed_drift)" begin
    suite = "OCRA-1:HOTP-SHA512-8:QA10-T1M"
    secret = OneTimePasswords.generate_secret(64)
    challenge = "SIG1230000"
    dt = DateTime(2022, 1, 1, 15, 41, 0)
    dt_m1 = dt - Minute(1)
    dt_p1 = dt + Minute(1)

    # codes for slots N-1, N, N+1
    code_m1 = OneTimePasswords.generate(OCRA(), secret; suite=suite,
      challenge=challenge, timestamp=dt_m1,
      digits=8, algorithm=:SHA512)
    code_0 = OneTimePasswords.generate(OCRA(), secret; suite=suite,
      challenge=challenge, timestamp=dt,
      digits=8, algorithm=:SHA512)
    code_p1 = OneTimePasswords.generate(OCRA(), secret; suite=suite,
      challenge=challenge, timestamp=dt_p1,
      digits=8, algorithm=:SHA512)

    # each code verifies within ±1min window
    for (t, code) in ((dt_m1, code_m1), (dt, code_0), (dt_p1, code_p1))
      @test OneTimePasswords.verify(OCRA(), secret, code;
        suite=suite, challenge=challenge,
        timestamp=t, allowed_drift=Minute(1),
        digits=8, algorithm=:SHA512)
    end

    # but code_0 does not verify at other slots without drift
    @test !OneTimePasswords.verify(OCRA(), secret, code_0;
      suite=suite, challenge=challenge,
      timestamp=dt_p1, allowed_drift=Second(0),
      digits=8, algorithm=:SHA512)
    @test !OneTimePasswords.verify(OCRA(), secret, code_0;
      suite=suite, challenge=challenge,
      timestamp=dt_m1, allowed_drift=Second(0),
      digits=8, algorithm=:SHA512)
  end

  @testset "URI formatting - HOTP & TOTP" begin
    b32 = OneTimePasswords.base32encode(Vector{UInt8}("1234"))
    hotp_uri = OneTimePasswords.uri(OneTimePasswords.HOTP(), b32, "u", "S";
      digits=6, counter=5, algorithm=:SHA1)
    @test startswith(hotp_uri, "otpauth://hotp/")
    @test occursin("secret=$(HTTP.URIs.escapeuri(b32))", hotp_uri)
    @test occursin("counter=5", hotp_uri)
    @test occursin("algorithm=SHA1", hotp_uri)

    totp_uri = OneTimePasswords.uri(OneTimePasswords.TOTP(), b32, "u", "S";
      digits=6, period=30)
    @test startswith(totp_uri, "otpauth://totp/")
    @test occursin("secret=$(HTTP.URIs.escapeuri(b32))", totp_uri)
    @test occursin("period=30", totp_uri)
  end

  @testset "URI escaping security" begin
    # Secret with '=' padding
    rawbytes = Vector{UInt8}("foo")
    sec = OneTimePasswords.base32encode(rawbytes)  # includes '='
    u_h = OneTimePasswords.uri(OneTimePasswords.HOTP(), sec, "acc", "iss";
      counter=1)
    u_t = OneTimePasswords.uri(OneTimePasswords.TOTP(), sec, "acc", "iss";
      period=30)
    # Secret should be percent-encoded in query to avoid malformed URI
    @test occursin("secret=$(HTTP.URIs.escapeuri(sec))", u_h)
    @test occursin("secret=$(HTTP.URIs.escapeuri(sec))", u_t)
  end

  @testset "OCRA provisioning URI formatting" begin
    sec = OneTimePasswords.generate_secret()
    acc = "alice@site.com"
    iss = "Bank/Ωrgañïzation"
    suite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
    challenge = "12345678"
    password = PIN_HASH
    u = OneTimePasswords.uri(OneTimePasswords.OCRA(), sec, acc, iss;
      suite=suite, digits=8, algorithm=:SHA256,
      counter=42, challenge=challenge, password=password,
      session_info="xyz", timestamp=123456)

    @test startswith(u, "otpauth://ocra/")
    @test occursin(HTTP.URIs.escapeuri("$iss:$acc"), u)
    @test occursin("suite=" * HTTP.URIs.escapeuri(suite), u)
    @test occursin("digits=8", u)
    @test occursin("algorithm=SHA256", u)
    @test occursin("counter=42", u)
    @test occursin("challenge=12345678", u)
    @test occursin("password=$password", u)
    @test occursin("sessioninfo=xyz", u)
    @test occursin("timestamp=123456", u)
  end

  @testset "OCRA Q-field length validation" begin
    # Q length > 64 (should be rejected)
    @test_throws Exception OneTimePasswords.generate(
      OneTimePasswords.OCRA(),
      "MFRGGZDFMZTWQ2LK",
      suite="OCRA-1:HOTP-SHA256-8:QA100"
    )

    # Q length < 4 (should be rejected)
    @test_throws Exception OneTimePasswords.generate(
      OneTimePasswords.OCRA(),
      "MFRGGZDFMZTWQ2LK",
      suite="OCRA-1:HOTP-SHA256-8:QA02")
  end

  @testset "Unicode / escaping in URIs" begin
    sec = OneTimePasswords.generate_secret(20)
    acc = "Björk O’Conor"
    iss = "🌞Sun/Örganization"
    u = OneTimePasswords.uri(OneTimePasswords.TOTP(), sec, acc, iss)
    @test occursin(HTTP.URIs.escapeuri(acc), u)
    @test occursin(HTTP.URIs.escapeuri(iss), u)
  end

  @testset "Round-trip secret → URI" begin
    s = OneTimePasswords.generate_secret(32)
    code = OneTimePasswords.generate(OneTimePasswords.TOTP(), s)
    u = OneTimePasswords.uri(OneTimePasswords.TOTP(), s, "bob", "ex";
      digits=6, period=30)
    @test occursin(HTTP.URIs.escapeuri(s), u)
  end

  @testset "URI smoke + HOTP/TOTP/OCRA round-trip" begin
    function parse_uri(uri::String)
      u = HTTP.URIs.URI(uri)
      kind = u.host
      lbl = HTTP.unescapeuri(lstrip(u.path, '/'))
      mp = Dict{String,String}()
      for (k, v) in HTTP.queryparams(u.query)
        mp[k] = HTTP.unescapeuri(v)
      end
      return kind, lbl, mp
    end
    # HOTP smoke
    secret, acct, iss = generate_secret(64), "bob@site.com", "MyApp"
    uri_h = uri(HOTP(), secret, acct, iss; digits=6, counter=42, algorithm=:SHA256)
    @test parse_uri(uri_h)[1] == "hotp"
    code_h = generate(HOTP(), secret, 42; digits=6, algorithm=:SHA256)
    @test verify(HOTP(), secret, 42, code_h; digits=6, algorithm=:SHA256)
    # TOTP smoke
    uri_t = uri(TOTP(), secret, acct, iss; digits=7, period=Second(15))
    @test parse_uri(uri_t)[1] == "totp"
    dt = DateTime(2023, 1, 1, 0, 0, 0)
    code_t = generate(TOTP(), secret; time=dt, period=Second(15), digits=7)
    @test verify(TOTP(), secret, code_t; time=dt, period=Second(15), digits=7)
    # OCRA smoke
    suite = "OCRA-1:HOTP-SHA512-8:QA10-T1M"
    uri_o = uri(OCRA(), secret, acct, iss;
      suite=suite,
      challenge="ABC123xyz",
      timestamp=floor(Int, datetime2unix(dt)),
      digits=8,
      algorithm=:SHA512)
    @test parse_uri(uri_o)[1] == "ocra"
    code_o = generate(OCRA(), secret;
      suite=suite,
      challenge="ABC123xyz",
      timestamp=dt,
      digits=8,
      algorithm=:SHA512)
    @test verify(OCRA(), secret, code_o;
      suite=suite,
      challenge="ABC123xyz",
      timestamp=dt,
      allowed_drift=Second(60),
      digits=8,
      algorithm=:SHA512)
  end

  @testset "QR-code helpers (SVG & PNG)" begin
    b32 = OneTimePasswords.base32encode(Vector{UInt8}("1234"))
    huri = OneTimePasswords.uri(OneTimePasswords.HOTP(), b32, "u", "S";
      counter=1)
    turi = OneTimePasswords.uri(OneTimePasswords.TOTP(), b32, "u", "S";
      period=Second(30))

    # SVG
    @test startswith(OneTimePasswords.qrcode(huri; format=:svg, size=80,
        border=1), "<svg")
    @test startswith(OneTimePasswords.qrcode(turi; format=:svg), "<svg")

    # PNG
    tmp = tempname() * ".png"
    path = OneTimePasswords.qrcode(huri; format="png", path=tmp)
    @test path == tmp
    @test isfile(tmp)
    bytes = read(tmp)
    @test bytes[1:8] == UInt8[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    rm(tmp; force=true)

    @test_throws ErrorException OneTimePasswords.qrcode(huri; format="bmp",
      path="foo.bmp")
    @test_throws ErrorException OneTimePasswords.qrcode(huri; format="jpg")
  end

  @testset "Edge cases & error handling" begin
    # invalid Base32
    @test_throws Exception OneTimePasswords.base32decode("!")
    # too few digits should throw (RFC requires ≥4)
    s = OneTimePasswords.generate_secret()
    @test_throws Exception OneTimePasswords.generate(OneTimePasswords.TOTP(),
      s; digits=1)
    # empty secret
    @test_throws Exception OneTimePasswords.verify(OneTimePasswords.TOTP(),
      "", "123456")
    # invalid padding
    @test_throws Exception OneTimePasswords.base32decode("A=====")
  end

  @testset "Digits validation security" begin
    sec = OneTimePasswords.generate_secret()
    # digits <=0 should throw
    @test_throws Exception OneTimePasswords.generate(OneTimePasswords.TOTP(),
      sec; digits=0)
    # too large digits should throw
    @test_throws Exception OneTimePasswords.generate(OneTimePasswords.TOTP(),
      sec; digits=15)
  end

  @testset "Secret length validation security" begin
    short20 = OneTimePasswords.generate_secret(20)
    # SHA1 works with 20
    @test OneTimePasswords.generate(OneTimePasswords.TOTP(), short20;
      algorithm=:SHA1) isa String
    # Too short secrets for stronger algorithms must throw
    @test_throws Exception OneTimePasswords.generate(OneTimePasswords.TOTP(),
      short20; algorithm=:SHA256)
    @test_throws Exception OneTimePasswords.generate(OneTimePasswords.TOTP(),
      short20; algorithm=:SHA512)

    short32 = OneTimePasswords.generate_secret(32)
    @test OneTimePasswords.generate(OneTimePasswords.TOTP(), short32;
      algorithm=:SHA256) isa String
    @test_throws Exception OneTimePasswords.generate(OneTimePasswords.TOTP(),
      short32; algorithm=:SHA512)

    sec64 = OneTimePasswords.generate_secret(64)
    @test OneTimePasswords.generate(OneTimePasswords.TOTP(), sec64;
      algorithm=:SHA512) isa String
  end

end