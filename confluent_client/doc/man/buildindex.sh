for i in *.ronn; do echo -n `head -n 1  $i|awk '{print $1}'`; echo " $i"; done > index.txt
