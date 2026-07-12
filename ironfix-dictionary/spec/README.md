# FIX specification data

`FIX44.xml` is the QuickFIX FIX 4.4 data dictionary, vendored verbatim from
the [QuickFIX project](https://github.com/quickfix/quickfix/blob/master/spec/FIX44.xml)
and distributed under the QuickFIX license (see
[LICENSE](https://github.com/quickfix/quickfix/blob/master/LICENSE)).

It is embedded into the `ironfix-dictionary` crate at compile time via
`include_str!` and exposed through `Dictionary::fix44()`.
