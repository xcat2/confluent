import glob
import os
yearsbyname = {}
namesbylicense = {}
filesbylicense = {}
allfiles = glob.glob('*.c')
allfiles.extend(glob.glob('*.y'))
allfiles.extend(glob.glob('compat/*.c'))
foundbin = False
for source in allfiles: # glob.glob('*.c'):
    if 'cmd-parse.c' == source:
        continue
    if not os.path.exists(source.replace('.c', '.o')):
        continue
    foundbin = True
    with open(source, 'r') as sourcein:
        cap = False
        thelicense = ''
        currnames = set([])
        for line in sourcein.readlines():
            if '$OpenBSD$' in line:
                continue
            if '/*' in line:
                cap = True
            elif '*/' in line:
                cap = False
                break
            elif cap:
                line = line[3:]
                if line.startswith('Author: '):
                    continue

                if line == 'Copyright (c) 1989, 1993\n':
                    name = 'The Regents of the University of California'
                    if name not in yearsbyname:
                        yearsbyname[name] = set([])
                    yearsbyname[name].add('1989')
                    yearsbyname[name].add('1993')
                    continue
                if line.startswith('Copyright'):
                    _, _, years, name = line.split(maxsplit=3)
                    if '>' in name:
                        name = name.split('>', 1)[0] + '>'
                    currnames.add(name)
                    if name not in yearsbyname:
                        yearsbyname[name] = set([])
                    if '-' in years:
                        strt, end = years.split('-')
                        for x in range(int(strt), int(end) + 1):
                            print(str(x))
                    else:
                        yearsbyname[name].add(years)
                    continue
                thelicense += line
        if thelicense not in namesbylicense:
            namesbylicense[thelicense] = set([])
        namesbylicense[thelicense].update(currnames)
        if thelicense not in filesbylicense:
            filesbylicense[thelicense] = set([])
        filesbylicense[thelicense].add(source)
#        with open(source + '.license', 'w') as liceout:
#            liceout.write(thelicense)

for license in namesbylicense:
    for file in sorted(filesbylicense[license]):
        print('File: ' + file)
    print('')
    for author in namesbylicense[license]:
        years = []
        for year in sorted(yearsbyname[author]):
            if not years:
                years.append(year)
                continue
            if int(years[-1].split('-')[-1]) == int(year) - 1:
                if '-' in years[-1]:
                    years[-1] = years[-1].split('-', 1)[0] + '-' + year
                else:
                    years[-1] = years[-1] + '-' + year
            else:
                years.append(year)
        authline = 'Copyright (c) {} {}'.format(','.join(years), author)
        print(authline)
    print("\n" + license + "\n\n")
