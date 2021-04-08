global ss:table[addr] of set[string];
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
    local s:string=c$http$user_agent;
    local a:addr=c$id$orig_h;
    if(a !in ss)
        ss[a]=set(to_lower(s));
    else
	    add ss[a][to_lower(s)];
}

event zeek_done()
{	
	for (ip in ss)
	{
		if(|ss[ip]|>=3)
			print ip," is a proxy";
	}
	#print ss;
}