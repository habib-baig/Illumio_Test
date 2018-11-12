Created a 4 sperate vectors storing valid rules for each combination of Direction(Inbound/outbound) and Protocol(Udp/Tcp)
to make searching more efficient.

As I used vectors for storing rules they allow faster sorting because of index based access. Already sorting the rules help us 
perform binary search on ranges.

Implemented custom sort function a list of rules based on starting ip address , if starting ip address is same 
sort based on end ip address.

Space Complexity == O(n)
Constructor Time Complexity == O(nlogn)
accept_packet function time complexity= o(logn)

