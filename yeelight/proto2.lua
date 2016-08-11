--require("bit")
-- yeelight UDP analysis
-- ______________________________________________[light]
pYee = Proto("Yee",  "Yeelight")

-- fType =ProtoField.bytes("Yee.Type","Type",base.HEX)
fType =ProtoField.bytes("Yee.Type","Type")
-- fUser = ProtoField.string("Mist.fUser","fUser","Text")
-- fLen = ProtoField.uint8("Mist.Length","Message Length",base.DEC)
fDevid1 = ProtoField.bytes("Yee.devid1","devid1","devid1")
fRND1 = ProtoField.bytes("Yee.RND1","RND1","RND1")
fRND2 = ProtoField.bytes("Yee.RND2","RND2","RND2")
fDevid2 = ProtoField.bytes("Yee.devid2","devid2","devid2")
fMsg = ProtoField.bytes("Yee.Tail","Tail","Tail")
pYee.fields = {fType
,fDevid1
,fRND1
,fDevid2
-- ,fRND2
,fMsg
}

function pYee.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = pYee.name;
	subtree = tree:add(pYee,buffer())
	local pos=0
	-- mType = buffer(0,4):uint()
	if string.upper(tostring(buffer(pos, 4))) == "21310020" then
	-- if string.upper(tostring(buffer(pos, 14))) == "213100200000000000D0A1F80000" then
		-- pos=8
	-- if mType == 0x21310020 then	-- ping
		-- subtree:add(fType,buffer(pos, 14)):append_text(" (ping)")
		subtree:add(fType,buffer(pos, 4)):append_text(" (prefix)")
		subtree:add(fDevid1,buffer(4, 8)):append_text(" (device id1)")
		subtree:add(fRND1,buffer(12, 6)):append_text(" (RND1)")
		subtree:add(fDevid2,buffer(18, 8)):append_text(" (device id2)")
		-- pos=pos+1
		-- subtree:add(fType,buffer(0, 4)):append_text(" (ping)")
	-- subtree:add(fRND2,buffer(23, 2)):append_text(" (RND2)")
		-- pos=pos+2
		-- subtree:add(fMsg,buffer(pos))
		subtree:add(fMsg,buffer(26))
	end
end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(54321,pYee)
-- ______________________________________________
