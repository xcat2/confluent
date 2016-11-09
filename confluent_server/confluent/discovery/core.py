# Copyright 2016 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This manages the detection and auto-configuration of nodes.
# Discovery sources may implement scans and may be passive or may provide
# both.

# The phases and actions:
# - Detect - Notice the existance of a potentially supported target
#        - Potentially apply a secure replacement for default credential
#           (perhaps using some key identifier combined with some string
#            denoting temporary use, and use confluent master integrity key
#            to generate a password in a formulaic way?)
#       - Do some universal reconfiguration if applicable (e.g. if something is
#         part of an enclosure with an optionally enabled enclosure manager,
#         check and request enclosure manager enablement
#       - Throughout all of this, at this phase no sensitive data is divulged,
#         only using credentials that are factory default or equivalent to
#         factory default
#       - Request transition to Locate
# - Locate - Use available cues to ascertain the physical location.  This may
#         be mac address lookup through switch or correlated by a server
#         enclosure manager.  If the location data suggests a node identity,
#         then proceed to the 'verify' state
# - Verify - Given the current information and candidate upstream verifier,
#            verify the authenticity of the servers claim in an automated way
#            if possible.  A few things may happen at this juncture
#               - Verification outright fails (confirmed negative response)
#                    - Audit log entry created, element is not *allowed* to
#                      proceed
#               - Verification not possible (neither good or bad)
#                   - If security policy is set to low, proceed to 'Manage'
#                   - Otherwise, log the detection event and stop (user
#                     would then manually bless the endpoint if applicable
#               - Verification succeeds
#                   - If security policy is set to strict (or manual, whichever
#                     word works best, note the successfull verification, but do
#                     not manage
#                   - Otherwise, proceed to 'Manage'
#  - Manage
#     - Create the node if autonode
#     - If there is not a defined ip address, collect the current LLA and use
#       that value.
#     - If no username/password defined, generate a unique password, 20 bytes
#       long, written to pass most complexity rules (15 random bytes, base64,
#       retry until uppercase, lowercase, digit, and symbol all present)
#     - Apply defined configuration to endpoint

# Passive-only auto-detection protocols:
# PXE

# Both passive and active
# SLP (passive mode listens for SLP DA and unicast interrogation of the system)
# mDNS
# SSD

# Also there are location provider concept.
# *

# We normalize discovered node data to the following pieces of information:
# * Detected node name (if available, from switch discovery or similar or
#   auto generated node name.
# * Model number
# * Model name
# * Serial number
# * System UUID (in x86 space, specifically whichever UUID would be in DMI)
# * Network interfaces and addresses
# * Switch connectivity information
# * enclosure information
# * Management TLS fingerprint if validated (by switch publication or enclosure)
# * System TLS fingerprint if validated (by switch publication or system manager)

_slp_services = set([
    'service:management-hardware.IBM:integrated-management-module2',

])
def add_validated_fingerprint(nodename, fingerprint, role='manager'):
    """Add a physically validated certificate fingerprint

    When a secure validater validates a fingerprint, this function is used to
    mark that fingerprint as validated.
    """
    pass

class DiscoveredNode(object):

    def __init__(self, uuid, serial=None, hwaddr=None, model=None,
                 modelnumber=None):
        """A representation of a discovered node

        This provides a representation of a discovered, but not yet located
        node.  The goal is to be given enough unique identifiers to help
        automatic and manual selection have information to find it.

        :param uuid: The UUID as it would appear in DMI table of the node
                     other UUIDs may appear, but a node is expected to be held
                     together by this UUID, and ideally would appear in PXE
                     packets.  For certain systems (e.g. enclosure managers),
                     this may be some other UUID if DMI table does not apply.
        :param serial:  Vendor assigned serial number for the node, if available
        :param hwaddr:  A primary MAC address that may be used for purposes of
                        locating the node.  For example mac address that is used
                        to search ethernet switches.
        :param model: A human readable description of the model.
        :param modelnumber:  If applicable, a numeric representation of the
                            model.

        """
        self.uuid = uuid
        self.serial = serial
        self.netinfo = netinfo
        self.fingerprints = {}
        self.model = model
        self.modelnumber = modelnumber

    def add_fingerprint(self, type, hashalgo, fingerprint):
        """Add a fingerprint to a discovered node

        Provide either an in-band certificate or manager certificate

        :param type: Indicates whether the certificate is a system or manager
                     certificate
        :param hashalgo: The algorithm used to generate fingerprint (SHA256,
                         SHA512)
        :param fingerprint: The signgature of the public certificate
        :return:
        """
        self.fingerprints[type] = (hashalgo, fingerprint)


    def identify(self, nodename):
        """Have discovered node check and auto add if appropriate

        After discovery examines a system, location plugins or client action
        may promote a system.  This is the function that handles promotion of
        a 'discovered' system to a full-fledged node.

        :param nodename: The node name to associate with this node
        :return:
        """
        # Ok, so at this point we want to pull in data about a node, and
        # attribute data may flow in one of a few ways depending on things:
        # If the newly defined node *would* have a hardwaremanagement.method
        # defined, then use that.  Otherwise, the node should suggest
        # it's own.  If it doesn't then we use the 'ipmi' default.
        # If it has a password explictly to use from user, use that.  Otherwise
        # generate a random password unique to the end point and set
        # that per-node.
        # If the would-be node has a defined hardwaremanagement.manager
        # and that defined value is *not* fe80, reprogram the BMC
        # to have that value.  Otherwise, if possible, take the current
        # fe80 and store that as hardwaremanagement.manager
        # If no fe80 possible *and* no existing value, error and do nothing
        # if security policy not set, this should only proceed if fingerprint is
        # validated by a secure validator.
        pass

def detect_endpoint(mac, peers, services):

def start_detection():
