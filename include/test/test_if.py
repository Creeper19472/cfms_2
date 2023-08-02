a = ["all", "deny"]

if not "all" in a and "deny" in a:
    print("aaa")

access_rules = {
    "__noinherit__": ["deny_rea", "den", "read"]
}

action = "read"

checkdeny = False

if not (f"deny_{action}" in (_noinherit:=access_rules.get("__noinherit__", []))) \
    and (not "deny" in _noinherit) and checkdeny:
    print(True)

if not (action in _noinherit) and not ("all" in _noinherit):
    print("True2")