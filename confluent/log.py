# Copyright 2013 IBM
# All rights reserved

# This module contains function to write out log type data.
# In this go around, log data is explicitly kept distinct from config data
# config data almost always retrieved by a particular key value and access
# pattern is random.  For logs, the access tends to be sequential.
#
# Current thought is to have a plain-text file and a secondary binary index
# file.  The index would track events and time intervals and the seek() value.
# Markers would be put into the plain text, allowing utility to rebuild
# index if something happens beyond the scope of this module's code.
#
# We can contemplate how to add value as an audit log.  The following
# possibilities could be explored:
#   - Forward Secure Sealing (like systemd).  Examine the algorithm and decide
#     if it is sufficient (their implementation, for example, seems hard
#     to protect against tampering as at least a few moments into the past
#     can always be manipulated....
#   - TPM PCRs.  Understand better what PCRs may be used/extended perhaps
#     per-indexed event..
