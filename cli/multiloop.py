import time
import sys, os

os.chdir("cli/")

for i in range(0,25):
    time.sleep(0.05)

    print("starting %s" % i)
    os.system("start python client.py")

time.sleep(20)

sys.exit()