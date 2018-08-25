I created a Rule class which would put each of these rules in a hashamp. I converted the Rule into a hashcode and put it in the hashmap.
I iterated over the csv and added to the hashmap based on whether they contained ranges or ip-addresses. The way I tested it was by creating different csv files and then testing it by passing in different rules to the accept_packet method. If I had more time, I would have added checks to make sure that the ip-address and ports are valid. I would also have added more csv files and tested more. 

If the ranges are large, especially for ip addresses, it takes a while for the hashmap to form. However, once the map is created, you can 
easily check if a range in valid or not in O(1) time. 