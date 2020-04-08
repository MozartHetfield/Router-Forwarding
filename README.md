# Dependencies:

echo "# Router-forwarding" >> README.md

git init

git add README.md

git commit -m "first commit"

git remote add origin https://github.com/MozartHetfield/Router-forwarding.git

git push -u origin master
                
# How to run:

fuser -k 6653/tcp 

python3 topo.py

"ping hx" where x is the number of the desired host

details will appear in the router window
