#!/usr/bin/env python2
#  test crap with netzob
from netzob.all import *
import binascii

# msg1 = PCAPImporter.readFile("/tmp/aaa/target_protocol.pcap").values()
arrF=[
	"/tmp/aaa/target_src_v1_session1.pcap"
	,"/tmp/aaa/target_src_v1_session2.pcap"
	# ,"/tmp/aaa/target_src_v1_session3.pcap"
]
samples = [
	#  "00ff2f000000"
	# ,"000010000000"
	# ,"00fe1f000000"
	# ,"000020000000"
	# ,"00ff1f000000"
	# ,"00ff1f000000"
	# ,"00ff2f000000"
	# ,"00fe1f000000"
	]
samples = [
	# "hello toto, what's up in France ?"
	# ,"hello netzob, what's up in UK ?"
	# ,"hello sygus, what's up in Germany ?"
	]
# f1 = Field(Raw(nbBytes=1))
# sym = Symbol([f1, f2, f3], messages=msgA)
msgA=[]
# msgA += [RawMessage(data=binascii.unhexlify(s)) for s in samples]	# hex
# msgA += [RawMessage(data=sample) for sample in samples]				# text
# msgA += PCAPImporter.readFile("/tmp/aaa/light32Conv.pcap").values()
# msgA += PCAPImporter.readFile("/tmp/aaa/light32Blb.pcap").values()
msgA += PCAPImporter.readFile("/tmp/aaa/light.pcap").values()
# msgA += PCAPImporter.readFile("/tmp/aaa/target_src_v1_session2.pcap").values()
# msgA = [[]+PCAPImporter.readFile(x).values() for x in arrF]
# msgA = map(lambda x: PCAPImporter.readFile(x).values(), arrF)
#
# PCAPImporter.readFile(x).values() for x in arrF
# aa=[PCAPImporter.readFile(x).values() for x in arrF]
# import ipdb; ipdb.set_trace()
# quit()
# print msgA
# msgA += PCAPImporter.readFile("/tmp/aaa/target_src_v1_session3.pcap").values()
# msgA += PCAPImporter.readFile("/tmp/aaa/scripts_MISCMAG/resources/capture1.pcap").values()
# msgA += PCAPImporter.readFile("/tmp/aaa/scripts_MISCMAG/resources/capture2.pcap").values()
# msgA += PCAPImporter.readFile("/tmp/aaa/scripts_MISCMAG/resources/capture3.pcap").values()
sym = Symbol(messages = msgA)
# ______________________________________________[split]
# Format.splitDelimiter(sym, ASCII("#"))				# split, delim
# Format.splitAligned(sym, doInternalSlick=True)		# split, align wunsch, !precise
Format.splitAligned(sym, doInternalSlick=False)		# split, align wunsch, precise, null!, best
# for s in syms: Format.splitAligned(s.fields[2], doInternalSlick=True)
# Format.splitStatic(sym)								# split
# Format.resetFormat(sym)								# reset format
# ______________________________________________[cluster]
# syms = Format.clusterByAlignment(msgA)				# cluster align
# Format.clusterByApplicativeData(msgA)					# cluster app, xxx
syms = Format.clusterByKeyField(sym, sym.fields[1])	# cluster field
# syms = Format.clusterBySize(msgA)						# cluster size
# ______________________________________________[manual]
# Format.mergeFields(sym.fields[0], sym.fields[1])	# merge field
# for s in syms.values():		# all
# 	s.fields[0].name='cmd'
# 	s.fields[1].name='EOF'
# syms["RESinfo"].fields[0].name='CMD'
# ______________________________________________[rel]
# for s in syms.values():		# relation
# 	rels = RelationFinder.findOnSymbol(s)
	# print rels
	# if len(rels):
	# 	for rel in rels: print " - " + rel["relation_type"] + ": '" + rel["x_attribute"] + "' of:"+ str('-'.join([f.name for f in rel["x_fields"]]))+" "+ str([v.getValues()[:] for v in rel["x_fields"]])+"\t<-> '" + rel["y_attribute"] + "' of:"+ str('-'.join([f.name for f in rel["y_fields"]]))+" " + str([v.getValues()[:] for v in rel["y_fields"]])
		# for r in rels:
		# 	rels[0]["x_fields"][0].domain = Size(rels[0]["y_fields"], factor=1/8.0)	# apply, size, xxx
		# 	rels[0]["x_fields"][0].name='size'
# ______________________________________________[graph]
# arrf=[
# 	"/tmp/aaa/target_src_v1_session1.pcap"
# 	,"/tmp/aaa/target_src_v1_session2.pcap"
# 	# ,"/tmp/aaa/target_src_v1_session3.pcap"
# ]
#
# asess = Session(msgA).abstract(syms.values())
# print Automata.generateChainedStatesAutomata(asess, syms.values()).generateDotCode()	# graph chain
# print Automata.generateOneStateAutomata(asess, syms.values()).generateDotCode()			# graph dot
# print Automata.generatePTAAutomata([Session(m).abstract(syms.values()) for m in [PCAPImporter.readFile(x).values() for x in arrf]], syms.values()).generateDotCode()	# graph PTA, list, arrf

# ______________________________________________[print]
# for x in msgA: print x		# ls log
# print syms
# print sym
print type(sym)
# for s in syms.values(): print s				# ls syms
for s in syms.values(): print s._str_debug()	# ls struct
	# for i in range(3): print repr(s.specialize())	# gen
quit()
# ______________________________________________
channelOut = UDPClient(remoteIP="127.0.0.1", remotePort=4242)
abstractionLayerOut = AbstractionLayer(channelOut, syms.values())
abstractionLayerOut.openChannel()

# # Visit the automata for n iteration
# state = automata.initialState
# for n in xrange(8):
#     state = state.executeAsInitiator(abstractionLayerOut)
# ______________________________________________
# def send_and_receive_symbol(symbol):
#     data = symbol.specialize()
#     print "[+] Sending: {0}".format(repr(data))
#     channelOut.write(data)
#     data = channelOut.read()
#     print "[+] Receiving: {0}".format(repr(data))

# Update symbol definition to allow a broader payload size
# syms["CMDencrypt"].fields[2].fields[2].domain =
# print Raw(nbBytes=(10, 120))

# for i in range(10):
#     send_and_receive_symbol(syms["CMDencrypt"])

# print symbol
