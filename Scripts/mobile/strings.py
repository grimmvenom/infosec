#!/usr/local/bin/python3
import os
import sys
import subprocess

directory = sys.argv[1]
#directory = "./Payload"

myfile = open("strings.txt", "w")

for root, directories, filenames in os.walk(directory):
    for filename in filenames:
        try:
            result = os.path.join(root, filename)
            myfile.write(">>>>> " + result + " <<<<<<\n")
            test = subprocess.check_output(["strings", result])
            myfile.write(test.decode("utf-8"))
            myfile.write("\n")
        except Exception as e:
            print("Error: ", e, "\n", filename)
            pass

print('Done Parsing')
