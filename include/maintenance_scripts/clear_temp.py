import os, sys

### UNSAFE!!!

if len(sys.argv) < 2:
    print("no root_abspath provided")
    sys.exit()

os.removedirs(f"{root_abspath}/content/temp")
