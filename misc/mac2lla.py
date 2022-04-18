def mac_to_lladdr(mac):
     macpieces = []
     mac = mac.replace('-', ':')
     for byte in mac.split(':'):
          macpieces.append(int(byte, 16))
     macpieces[0] = macpieces[0] ^ 2
     llapieces = [(macpieces[0] << 8) + macpieces[1], (macpieces[2] << 8) + 0xff, 0xfe00 + macpieces[3], (macpieces[4] << 8) + macpieces[5]]
     return 'fe80::{:x}:{:x}:{:x}:{:x}'.format(*llapieces)

if __name__ == '__main__':
    import sys
    print(mac_to_lladdr(sys.argv[1]))
