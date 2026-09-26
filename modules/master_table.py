# modules/master_table.py
"""files/Master_Table.xlsx as data: the manually tested outcome of every SPF/DMARC combination.

Keys are (SPF state, DMARC tags as written in the record). The SPF state is "-all", "~all",
"?all", "+all", "noall" (an SPF record without an 'all') or "nospf". The DMARC part is None
for no DMARC record, else (p, sp, aspf) with None for a tag the record leaves out.

test.py fails if this drifts from the spreadsheet. After updating the spreadsheet, run
`python3 -m modules.master_table` to rewrite this file from it.
"""

SPREADSHEET_SPF = {
    "-all": "-all",
    "all-": "-all",
    "all~": "~all",
    "all?": "?all",
    "all+": "+all",
    "No All": "noall",
    "No SPF": "nospf",
}


def load_spreadsheet(path):
    """Read the master table into the TABLE format, in spreadsheet row order."""
    import openpyxl

    rows = openpyxl.load_workbook(path).worksheets[0].iter_rows(values_only=True, min_row=2)
    table = {}
    for spf, dmarc, code in (row[:3] for row in rows if row[0]):
        if dmarc == "No DMARC":
            key = (SPREADSHEET_SPF[spf], None)
        else:
            tags = dict(tag.strip().split("=") for tag in dmarc.split(","))
            key = (SPREADSHEET_SPF[spf], (tags["p"], tags.get("sp"), tags.get("aspf")))
        if key in table:
            raise ValueError(f"duplicate row in {path}: {spf} | {dmarc}")
        table[key] = int(code)
    return table


def render(table):
    return "TABLE = {\n" + "".join(f"    {key!r}: {code},\n" for key, code in table.items()) + "}\n"


TABLE = {
    ('-all', None): 0,
    ('-all', ('quarantine', 'none', None)): 1,
    ('-all', ('reject', 'none', None)): 1,
    ('-all', ('none', 'none', 'r')): 1,
    ('-all', ('none', 'none', 's')): 1,
    ('-all', ('quarantine', 'none', 'r')): 1,
    ('-all', ('reject', 'none', 'r')): 1,
    ('-all', ('none', 'quarantine', 'r')): 2,
    ('-all', ('none', 'reject', 'r')): 2,
    ('-all', ('none', None, None)): 4,
    ('-all', ('none', None, 'r')): 4,
    ('-all', ('none', None, 's')): 4,
    ('-all', ('none', 'quarantine', None)): 5,
    ('-all', ('none', 'reject', None)): 5,
    ('-all', ('none', 'none', None)): 7,
    ('-all', ('quarantine', None, None)): 8,
    ('-all', ('reject', None, None)): 8,
    ('-all', ('quarantine', 'quarantine', None)): 8,
    ('-all', ('quarantine', 'reject', None)): 8,
    ('-all', ('reject', 'quarantine', None)): 8,
    ('-all', ('reject', 'reject', None)): 8,
    ('-all', ('none', 'quarantine', 's')): 8,
    ('-all', ('none', 'reject', 's')): 8,
    ('-all', ('quarantine', 'none', 's')): 8,
    ('-all', ('quarantine', 'quarantine', 'r')): 8,
    ('-all', ('quarantine', 'quarantine', 's')): 8,
    ('-all', ('quarantine', 'reject', 'r')): 8,
    ('-all', ('quarantine', 'reject', 's')): 8,
    ('-all', ('reject', 'none', 's')): 8,
    ('-all', ('reject', 'quarantine', 'r')): 8,
    ('-all', ('reject', 'quarantine', 's')): 8,
    ('-all', ('reject', 'reject', 'r')): 8,
    ('-all', ('reject', 'reject', 's')): 8,
    ('?all', ('none', None, 'r')): 0,
    ('?all', ('none', 'none', 'r')): 0,
    ('?all', None): 0,
    ('?all', ('quarantine', 'none', 'r')): 1,
    ('?all', ('quarantine', 'none', 's')): 1,
    ('?all', ('reject', 'none', 'r')): 1,
    ('?all', ('reject', 'none', 's')): 1,
    ('?all', ('none', None, None)): 4,
    ('?all', ('none', 'none', None)): 4,
    ('?all', ('none', None, 's')): 4,
    ('?all', ('none', 'none', 's')): 4,
    ('?all', ('none', 'quarantine', None)): 5,
    ('?all', ('none', 'reject', None)): 5,
    ('?all', ('none', 'quarantine', 'r')): 5,
    ('?all', ('none', 'quarantine', 's')): 5,
    ('?all', ('none', 'reject', 'r')): 5,
    ('?all', ('none', 'reject', 's')): 5,
    ('?all', ('quarantine', 'none', None)): 6,
    ('?all', ('reject', 'none', None)): 6,
    ('?all', ('quarantine', None, None)): 8,
    ('?all', ('reject', None, None)): 8,
    ('?all', ('quarantine', 'quarantine', None)): 8,
    ('?all', ('quarantine', 'reject', None)): 8,
    ('?all', ('reject', 'quarantine', None)): 8,
    ('?all', ('reject', 'reject', None)): 8,
    ('?all', ('quarantine', 'quarantine', 'r')): 8,
    ('?all', ('quarantine', 'quarantine', 's')): 8,
    ('?all', ('quarantine', 'reject', 'r')): 8,
    ('?all', ('quarantine', 'reject', 's')): 8,
    ('?all', ('reject', 'quarantine', 'r')): 8,
    ('?all', ('reject', 'quarantine', 's')): 8,
    ('?all', ('reject', 'reject', 'r')): 8,
    ('?all', ('reject', 'reject', 's')): 8,
    ('+all', ('none', None, None)): 4,
    ('+all', ('quarantine', None, None)): 4,
    ('+all', ('reject', None, None)): 4,
    ('+all', ('none', 'none', None)): 4,
    ('+all', ('none', 'quarantine', None)): 4,
    ('+all', ('none', 'reject', None)): 4,
    ('+all', ('none', None, 'r')): 4,
    ('+all', ('none', None, 's')): 4,
    ('+all', ('quarantine', 'none', None)): 4,
    ('+all', ('quarantine', 'quarantine', None)): 4,
    ('+all', ('quarantine', 'reject', None)): 4,
    ('+all', ('reject', 'none', None)): 4,
    ('+all', ('reject', 'quarantine', None)): 4,
    ('+all', ('reject', 'reject', None)): 4,
    ('+all', ('none', 'none', 'r')): 4,
    ('+all', ('none', 'none', 's')): 4,
    ('+all', ('none', 'quarantine', 'r')): 4,
    ('+all', ('none', 'quarantine', 's')): 4,
    ('+all', ('none', 'reject', 'r')): 4,
    ('+all', ('none', 'reject', 's')): 4,
    ('+all', ('quarantine', 'none', 'r')): 4,
    ('+all', ('quarantine', 'none', 's')): 4,
    ('+all', ('quarantine', 'quarantine', 'r')): 4,
    ('+all', ('quarantine', 'quarantine', 's')): 4,
    ('+all', ('quarantine', 'reject', 'r')): 4,
    ('+all', ('quarantine', 'reject', 's')): 4,
    ('+all', ('reject', 'none', 'r')): 4,
    ('+all', ('reject', 'none', 's')): 4,
    ('+all', ('reject', 'quarantine', 'r')): 4,
    ('+all', ('reject', 'quarantine', 's')): 4,
    ('+all', ('reject', 'reject', 'r')): 4,
    ('+all', ('reject', 'reject', 's')): 4,
    ('+all', None): 4,
    ('~all', ('none', 'none', None)): 0,
    ('~all', None): 0,
    ('~all', ('quarantine', 'none', None)): 1,
    ('~all', ('reject', 'none', None)): 1,
    ('~all', ('none', 'quarantine', None)): 2,
    ('~all', ('none', 'reject', None)): 2,
    ('~all', ('none', None, 'r')): 2,
    ('~all', ('none', None, 's')): 2,
    ('~all', ('none', 'quarantine', 'r')): 2,
    ('~all', ('none', 'quarantine', 's')): 2,
    ('~all', ('none', 'reject', 'r')): 2,
    ('~all', ('none', 'reject', 's')): 2,
    ('~all', ('none', 'none', 'r')): 7,
    ('~all', ('none', 'none', 's')): 7,
    ('~all', ('none', None, None)): 0,
    ('~all', ('quarantine', None, None)): 8,
    ('~all', ('reject', None, None)): 8,
    ('~all', ('quarantine', 'quarantine', None)): 8,
    ('~all', ('quarantine', 'reject', None)): 8,
    ('~all', ('reject', 'quarantine', None)): 8,
    ('~all', ('reject', 'reject', None)): 8,
    ('~all', ('quarantine', 'none', 'r')): 8,
    ('~all', ('quarantine', 'none', 's')): 8,
    ('~all', ('quarantine', 'quarantine', 'r')): 8,
    ('~all', ('quarantine', 'quarantine', 's')): 8,
    ('~all', ('quarantine', 'reject', 'r')): 8,
    ('~all', ('quarantine', 'reject', 's')): 8,
    ('~all', ('reject', 'none', 'r')): 8,
    ('~all', ('reject', 'none', 's')): 8,
    ('~all', ('reject', 'quarantine', 'r')): 8,
    ('~all', ('reject', 'quarantine', 's')): 8,
    ('~all', ('reject', 'reject', 'r')): 8,
    ('~all', ('reject', 'reject', 's')): 8,
    ('noall', ('none', None, 'r')): 0,
    ('noall', ('none', 'none', 'r')): 0,
    ('noall', None): 0,
    ('noall', ('quarantine', 'none', 'r')): 1,
    ('noall', ('quarantine', 'none', 's')): 1,
    ('noall', ('reject', 'none', 'r')): 1,
    ('noall', ('reject', 'none', 's')): 1,
    ('noall', ('none', None, None)): 4,
    ('noall', ('none', 'none', None)): 4,
    ('noall', ('none', None, 's')): 4,
    ('noall', ('none', 'none', 's')): 4,
    ('noall', ('none', 'quarantine', None)): 5,
    ('noall', ('none', 'reject', None)): 5,
    ('noall', ('none', 'quarantine', 'r')): 5,
    ('noall', ('none', 'quarantine', 's')): 5,
    ('noall', ('none', 'reject', 'r')): 5,
    ('noall', ('none', 'reject', 's')): 5,
    ('noall', ('quarantine', 'none', None)): 6,
    ('noall', ('reject', 'none', None)): 6,
    ('noall', ('quarantine', None, None)): 8,
    ('noall', ('reject', None, None)): 8,
    ('noall', ('quarantine', 'quarantine', None)): 8,
    ('noall', ('quarantine', 'reject', None)): 8,
    ('noall', ('reject', 'quarantine', None)): 8,
    ('noall', ('reject', 'reject', None)): 8,
    ('noall', ('quarantine', 'quarantine', 'r')): 8,
    ('noall', ('quarantine', 'quarantine', 's')): 8,
    ('noall', ('quarantine', 'reject', 'r')): 8,
    ('noall', ('quarantine', 'reject', 's')): 8,
    ('noall', ('reject', 'quarantine', 'r')): 8,
    ('noall', ('reject', 'quarantine', 's')): 8,
    ('noall', ('reject', 'reject', 'r')): 8,
    ('noall', ('reject', 'reject', 's')): 8,
    ('nospf', None): 0,
    ('nospf', ('none', 'none', 'r')): 2,
    ('nospf', ('none', 'none', 's')): 2,
    ('nospf', ('none', None, None)): 4,
    ('nospf', ('quarantine', None, None)): 8,
    ('nospf', ('reject', None, None)): 8,
    ('nospf', ('none', 'none', None)): 8,
    ('nospf', ('none', 'quarantine', None)): 8,
    ('nospf', ('none', 'reject', None)): 8,
    ('nospf', ('none', None, 'r')): 8,
    ('nospf', ('none', None, 's')): 8,
    ('nospf', ('quarantine', 'none', None)): 8,
    ('nospf', ('quarantine', 'quarantine', None)): 8,
    ('nospf', ('quarantine', 'reject', None)): 8,
    ('nospf', ('reject', 'none', None)): 8,
    ('nospf', ('reject', 'quarantine', None)): 8,
    ('nospf', ('reject', 'reject', None)): 8,
    ('nospf', ('none', 'quarantine', 'r')): 8,
    ('nospf', ('none', 'quarantine', 's')): 8,
    ('nospf', ('none', 'reject', 'r')): 8,
    ('nospf', ('none', 'reject', 's')): 8,
    ('nospf', ('quarantine', 'none', 'r')): 8,
    ('nospf', ('quarantine', 'none', 's')): 8,
    ('nospf', ('quarantine', 'quarantine', 'r')): 8,
    ('nospf', ('quarantine', 'quarantine', 's')): 8,
    ('nospf', ('quarantine', 'reject', 'r')): 8,
    ('nospf', ('quarantine', 'reject', 's')): 8,
    ('nospf', ('reject', 'none', 'r')): 8,
    ('nospf', ('reject', 'none', 's')): 8,
    ('nospf', ('reject', 'quarantine', 'r')): 8,
    ('nospf', ('reject', 'quarantine', 's')): 8,
    ('nospf', ('reject', 'reject', 'r')): 8,
    ('nospf', ('reject', 'reject', 's')): 8,
}


if __name__ == "__main__":
    import os

    module = os.path.abspath(__file__)
    with open(module) as f:
        source = f.read()
    before, rest = source.split("TABLE = {\n", 1)
    after = rest.split("\n}\n", 1)[1]
    spreadsheet = os.path.join(os.path.dirname(module), "..", "files", "Master_Table.xlsx")
    with open(module, "w") as f:
        f.write(before + render(load_spreadsheet(spreadsheet)) + after)
