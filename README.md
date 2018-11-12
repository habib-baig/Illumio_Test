Created a 4 sperate vectors storing valid rules for each combination of Direction(Inbound/outbound) and Protocol(Udp/Tcp)
to make searching more efficient.<br/>

As I used vectors for storing rules they allow faster sorting because of index based access. Already sorting the rules help us 
perform binary search on ranges.<br/>

Implemented custom sort function a list of rules based on starting ip address , if starting ip address is same 
sort based on end ip address.<br/>


Space Complexity == O(n)<br/>
Constructor Time Complexity == O(nlogn) <br/>
accept_packet function time complexity= o(logn) -- Binary Search<br/>

Another way:<br/>
We could have dumped the rules in a database and applied indexes on Ip address to make search faster. Becasue in real life stuation the accept_packet fucntion should have close to constant time complexity.
If I had more time I would have implmented the solution with Hashmap by expanding and storing the expanded Ip ranges and a nested hasmap for storing the port numbers. But this approach will be inefficient in terms of memory <br/>
suppose we have 50k rules, each with average port range= 1000 and Ip range= 10,000
then total memory requires would have been close (50,000* 1000* 10,000)= 500 GB which is highly infisible hence although this approach has O(1) time complexity. Dictionaries will consume Huge memory.

Hence, I think Binary search is the most optimal way of implementing considering memory and time complexity tradeoff. Hence, In memory caching of data and binary search on it is the optimal way.
