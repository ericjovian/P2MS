# P2MS
implementing P2MS script using pycryptodome
<br/><br/>
To run P2MS.py:<br/>
open terminal in the current folder where the program is located
then use command:<br/>
 <h4> python3 p2ms.py #number of M# #number of N# </h4><br/>
eq:<br/>
  <h4>python3 p2ms.py 2 3</h4><br/>
this way, the program will generate an M number of signature and output it to “scriptSig.txt” and N number of public key to “scriptPubKey.txt”. 
<br/><br/>
The public key will be signed with"CSCI301 Contemporary topic in security" message.<br/>
then to verify:
<br/>
run the verify.py using the command:<br/>
 <h4>python3 verify.py #Signature txt file# #public key txt file#</h4><br/>
eq:<br/>
 <h4>>>> python3 verify.py scriptSig.txt scriptpubKey.txt</h4><br/>
 
