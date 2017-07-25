
def add_score(c, x):
	if blocked.has_key(c):
		return
	if not score.has_key(c):
		score[c] = x
	else:
		score[c] += x
	if score[c] >= thres:
		print c
		blocked[c] = True

def add(c, x):
	add_score((c[0], c[2]), x)
	add_score((c[1], c[3]), x)

track = {}
def sniffer(pkt):
        global sample
        if sample > limit:
            score.clear()
            sample = 0
        sample += 1

	ip = pkt.payload
	tcp = ip.payload
	c, s = conn(ip.src, ip.dst, tcp.sport, tcp.dport)

	if tcp.flags & dpkt.tcp.TH_SYN != 0:
		track[c] = []
	if not track.has_key(c):
		return

	if tcp.flags & dpkt.tcp.TH_FIN != 0 or tcp.flags & dpkt.tcp.TH_RST != 0:
		del track[c]
		return

        # SS Original
	# if tcp.flags & dpkt.tcp.TH_PUSH != 0:
	# 	track[c].append((entropy(dist(str(tcp.payload))), s))
	# 	if len(track[c]) >= 4:
	# 		if track[c][0][0] > 4.8 or \
	# 		   (track[c][0][0] > 4.4 and track[c][1][0] > 4.2) or \
	# 		   (track[c][0][0] > 4.2 and track[c][2][0] > 4.2 and \
	# 			track[c][0][1] == track[c][2][1]) or \
	# 		   track[c][0][1] == track[c][1][1]:
	# 			add(c, 1)
	# 		else:
	# 			add(c, -1)
	# 		del track[c]

        # SSR
	if tcp.flags & dpkt.tcp.TH_PUSH != 0:
	        track[c].append(len(tcp.payload))
		if len(track[c]) >= 32:
                        e = pow(entropy(track[c][8:32]), 2)
                        if e > 9:
				add(c, 1)
			else:
				add(c, -1)
			del track[c]

sniff(filter='tcp', store=False, prn=sniffer)
