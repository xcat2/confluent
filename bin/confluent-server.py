import sys
import os
path = os.path.dirname(os.path.realpath(__file__))
path = os.path.realpath(os.path.join(path, '..'))
sys.path.append(path)
from confluent import main

#import cProfile
#import time
#p = cProfile.Profile(time.clock)
#p.enable()
#try:
main.run()
#except:
#   pass
#p.disable()
#p.print_stats(sort='cumulative')
#p.print_stats(sort='time')
