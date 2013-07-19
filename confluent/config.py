# Copyright 2013 IBM
# All rights reserved

# This would be similar to Table.pm functionality
# Two backends
#  simple plain JSON
#  redis

# This time around, expression based values will be parsed when set, and the
# parsing results will be stored rather than parsing on every evaluation
# Additionally, the option will be made available to use other attributes
# as well as the $1, $2, etc extracted from nodename.  Left hand side can
# be requested to customize $1 and $2, but it is not required

# In JSON mode, will just read and write entire thing, with a comment
# to dissuade people from hand editing.

# In JSON mode, a file for different categories (site, nodes, etc)
# in redis, each category is a different database number
