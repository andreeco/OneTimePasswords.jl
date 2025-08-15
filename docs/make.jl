using OTPs
using Documenter

DocMeta.setdocmeta!(OTPs, :DocTestSetup, :(using OTPs); recursive=true)

makedocs(;
    modules=[OTPs],
    authors="André Herling <andreeco@herling.pro>",
    sitename="OTPs.jl",
    format=Documenter.HTML(;
        canonical="https://andreeco.github.io/OTPs.jl",
        edit_link="main",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
    ],
)

deploydocs(;
    repo="github.com/andreeco/OTPs.jl",
    devbranch="main",
)
