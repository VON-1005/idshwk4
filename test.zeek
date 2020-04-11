@load base/frameworks/sumstats

event zeek_init()
{
	local r1 = SumStats::Reducer($stream = "reply.lookup", $apply = set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream = "404.lookup", $apply = set(SumStats::UNIQUE));
	SumStats::create([$name = "404.summary",
			  $epoch = 10mins,
			  $reducers = set(r1, r2),
			  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
			  {
				local res1 = result["reply.lookup"];
				local res2 = result["404.lookup"];
				if (res2$num > 2){
					if (res2$num / res1$num > 0.2){
						if (res2$unique / res2$num > 0.5){
							print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, res2$num, res2$unique);
						}
					}
				}
			  }]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("reply.lookup", [$host = c$id$orig_h], [$str = cat(c$http$status_code)]);
	if (c$http$status_code == 404){
		SumStats::observe("404.lookup", [$host = c$id$orig_h], [$str = cat(c$http$status_code)]);
	}
}
