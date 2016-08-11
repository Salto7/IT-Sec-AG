--require("bit")
-- yeelight UDP analysis
-- ______________________________________________[light]
pYee = Proto("Yee",  "Yeelight")

-- fType =ProtoField.bytes("Yee.Type","Type",base.HEX)
fType =ProtoField.bytes("Yee.Type","Type")
-- fUser = ProtoField.string("Mist.fUser","fUser","Text")
-- fLen = ProtoField.uint8("Mist.Length","Message Length",base.DEC)
fX1 = ProtoField.bytes("Yee.X1","X1","X1")
fMsg = ProtoField.bytes("Yee.Tail","Tail","Tail")
pYee.fields = {fType,fX1,fMsg}
					
function pYee.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = pYee.name;
	subtree = tree:add(pYee,buffer())
	local pos=0
	-- mType = buffer(0,4):uint()
	if string.upper(tostring(buffer(pos, 14))) == "213100200000000000D0A1F80000" then
		-- pos=8
	-- if mType == 0x21310020 then	-- ping
		-- subtree:add(fType,buffer(pos, 14)):append_text(" (ping)")
		subtree:add(fType,buffer(pos, 14)):append_text(" (ping)")
		-- pos=pos+1
		-- subtree:add(fType,buffer(0, 4)):append_text(" (ping)")
		subtree:add(fX1,buffer(15, 2)):append_text(" (RND)")
		-- pos=pos+2
		-- subtree:add(fMsg,buffer(pos))
		subtree:add(fMsg,buffer(17))
	end
end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(54321,pYee)
-- ______________________________________________
