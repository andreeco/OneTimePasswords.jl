using OneTimePasswords
using Documenter

DocMeta.setdocmeta!(OneTimePasswords, :DocTestSetup, :(using OneTimePasswords); recursive=true)

makedocs(;
    modules=[OneTimePasswords],
    authors="André Herling <andreeco@herling.pro>",
    sitename="OneTimePasswords.jl",
    format=Documenter.HTML(;
        canonical="https://andreeco.github.io/OneTimePasswords.jl",
        edit_link="main",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
    ],
)

deploydocs(;
    repo="github.com/andreeco/OneTimePasswords.jl",
    devbranch="main",
)
