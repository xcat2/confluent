import sys
import os
path = os.path.dirname(os.path.realpath(__file__))
path = os.path.realpath(os.path.join(path, '..'))
sys.path.append(path)
from confluent import main

main.run()
