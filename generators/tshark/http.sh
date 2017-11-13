tshark -V -Y "http.response || http.request || http.request.uri.path" -r $1 | grep "Host\|Referer\|X-Requested-With"
