# DNS Resolver
A DNS resolver that involves building a query sending it and parsing the response. The main goal of this project is to show the route that a DNS request when requested takes from root servers to various Name servers and finally to dedicated authoritative servers that contain answers for the query. The interaction is made in the form of a command-line UI where user inserts various commands to interact.

# Commands Used
 ## `server a.b.c.d`
writing the IP address or name of the server to which the user want to send request for a query.
 ## `server root` 
Select a random root server in which user wants to send a query to.
 ## `lookup hostname` or `l hostname`
Retrives the IP address of ***type A*** associated to the hostname. IF there is any entry with the dedicated hostname that uses the query otherwise starts an
iterative DNS query
 ## `lookup hostame type` 
 Retrives a resource record or answer to the query that was sent of specific type. The types can be  ***A***, ***NS***, ***MX***, ***CNAME***, ***AAAA*** 
 ## `verbose on` or `verbose off`
 Turns the verbose tracing on or off. Initially, verbose tracing is off and whenver you try to send a query what you get is straight response from authoritative name
 servers and not how it got it. When verbose tracing is on you can see which all servers query was sent to and how was response was recieved.
 ## `dump`
 With the help of this command one can the system prints all the resource records that are present in the cache and have not expired.
 ## `reset`
 This command removes all the resource records from the cache, keeping only the root name servers in the cache.
 ## `quit`
 this is the termination command which terminates the program.
